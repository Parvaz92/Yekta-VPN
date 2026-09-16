use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::{AetherError, Result};

/// Gemini domains that must route through anti-sanction DNS
const GEMINI_DOMAINS: &[&str] = &[
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "alkalinetransmit-pa.googleapis.com",
    "bard.google.com",
    "proactivity-pa.googleapis.com",
];

/// Anti-sanction DNS servers (Plain UDP, port 53)
const ANTI_SANCTION_DNS: &[&str] = &[
    "10.202.10.202",   // 403.online
    "10.202.10.102",   // 403.online
    "78.157.42.100",   // Electro
    "78.157.42.101",   // Electro
    "178.22.122.100",  // Shecan
    "185.51.200.2",    // Shecan
];

/// Default fast DNS (Cloudflare/Google) for non-Gemini traffic
const DEFAULT_DNS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "9.9.9.9",
];

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_CONCURRENT_QUERIES: usize = 32;

/// Cached DNS response
#[derive(Clone)]
struct CachedResponse {
    data: Vec<u8>,
    expires: Instant,
}

/// Smart DNS Split Engine
pub struct SmartDnsSplit {
    /// In-memory cache for Gemini responses (RAM only)
    cache: Arc<RwLock<HashMap<Vec<u8>, CachedResponse>>>,
    /// Semaphore to limit concurrent queries
    semaphore: Arc<Semaphore>,
    /// Anti-sanction DNS sockets (pre-connected)
    anti_sanction_sockets: Arc<Vec<Arc<UdpSocket>>>,
    /// Default DNS sockets (pre-connected)
    default_sockets: Arc<Vec<Arc<UdpSocket>>>,
}

impl SmartDnsSplit {
    /// Create a new Smart DNS Split engine
    pub async fn new() -> Result<Self> {
        let mut anti_sanction_sockets = Vec::new();
        let mut default_sockets = Vec::new();

        // Pre-connect anti-sanction DNS sockets
        for server in ANTI_SANCTION_DNS {
            let addr: SocketAddr = format!("{}:{}", server, DNS_PORT).parse()
                .map_err(|e| AetherError::Other(format!("Invalid anti-sanction DNS {}: {}]", server, e)))?;
            let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await
                .map_err(AetherError::Io)?;
            sock.connect(addr).await.map_err(AetherError::Io)?;
            // IMPORTANT: these queries must leave through the TUNNEL, not the
            // carrier. protect_socket() routes them outside the VPN, where every
            // one of these resolvers is either blocked (Iran) or simply
            // unreachable. The previous build protected them, which is why AI
            // Mode never resolved anything even when the flag was on.
            // No protect_socket() here.
            anti_sanction_sockets.push(Arc::new(sock));
        }

        // Pre-connect default DNS sockets
        for server in DEFAULT_DNS {
            let addr: SocketAddr = format!("{}:{}", server, DNS_PORT).parse()
                .map_err(|e| AetherError::Other(format!("Invalid default DNS {}: {}]", server, e)))?;
            let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await
                .map_err(AetherError::Io)?;
            sock.connect(addr).await.map_err(AetherError::Io)?;
            default_sockets.push(Arc::new(sock));
        }

        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
            anti_sanction_sockets: anti_sanction_sockets.into(),
            default_sockets: default_sockets.into(),
        })
    }

    /// Check if a domain is a Gemini domain (exact or subdomain match)
    fn is_gemini_domain(name: &str) -> bool {
        let name = name.to_lowercase();
        GEMINI_DOMAINS.iter().any(|d| {
            name == *d || name.ends_with(&format!(".{}", d))
        })
    }

    /// Build a DNS query packet
    fn build_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
        let id = rand::random::<u16>();
        let mut q = Vec::with_capacity(32 + name.len());
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
        q.extend_from_slice(&[0x00, 0x01]); // 1 question
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in name.split('.') {
            if label.is_empty() { continue; }
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0x00);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // class IN
        (q, id)
    }

    /// Check if response matches our query
    fn response_matches(resp: &[u8], expected_id: u16, expected_name: &str, expected_qtype: u16) -> bool {
        if resp.len() < 12 { return false; }
        if u16::from_be_bytes([resp[0], resp[1]]) != expected_id { return false; }
        if resp[2] & 0x80 == 0 { return false; } // not a response
        if u16::from_be_bytes([resp[4], resp[5]]) != 1 { return false; } // not 1 question

        let mut pos = 12;
        for label in expected_name.split('.') {
            if label.is_empty() { continue; }
            let len = match resp.get(pos) { Some(v) => *v as usize, None => return false };
            if len != label.len() { return false; }
            pos += 1;
            let end = match pos.checked_add(len) { Some(v) if v <= resp.len() => v, _ => return false };
            if !resp[pos..end].eq_ignore_ascii_case(label.as_bytes()) { return false; }
            pos = end;
        }
        if resp.get(pos) != Some(&0) { return false; }
        pos += 1;
        if pos + 4 > resp.len() { return false; }
        u16::from_be_bytes([resp[pos], resp[pos + 1]]) == expected_qtype
    }

    /// Extract first A record from response
    fn extract_a_record(resp: &[u8]) -> Option<Ipv4Addr> {
        if resp.len() < 12 { return None; }
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
        let mut pos = 12;
        // skip question
        for _ in 0..u16::from_be_bytes([resp[4], resp[5]]) as usize {
            pos = Self::skip_name(resp, pos)?;
            pos += 4; // type + class
        }
        // parse answers
        for _ in 0..ancount {
            pos = Self::skip_name(resp, pos)?;
            if pos + 10 > resp.len() { return None; }
            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > resp.len() { return None; }
            if rtype == 1 && rdlen == 4 { // A record
                return Some(Ipv4Addr::new(resp[pos], resp[pos+1], resp[pos+2], resp[pos+3]));
            }
            pos += rdlen;
        }
        None
    }

    /// Skip a domain name (handles compression)
    fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
        for _ in 0..20 {
            if pos >= buf.len() { return None; }
            let len = buf[pos];
            if len & 0xC0 == 0xC0 {
                return Some(pos + 2);
            }
            if len == 0 {
                return Some(pos + 1);
            }
            pos += 1 + len as usize;
        }
        None
    }

    /// Query multiple DNS servers in parallel, return first successful response
    async fn parallel_query(&self, sockets: Arc<Vec<Arc<UdpSocket>>>, query: Vec<u8>, expected_id: u16, name: String) -> Result<Vec<u8>> {
        let permit = self.semaphore.acquire().await.map_err(|_| AetherError::Other("semaphore closed".into()))?;

        let mut handles = Vec::new();
        let query = Arc::new(query);
        let name = Arc::new(name);
        for sock in sockets.iter().cloned() {
            let query = query.clone();
            let name = name.clone();
            handles.push(tokio::spawn(async move {
                let deadline = Instant::now() + QUERY_TIMEOUT;
                sock.send(&query).await.ok()?;
                let mut buf = [0u8; 4096];
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() { return None; }
                    let n = timeout(remaining, sock.recv(&mut buf)).await.ok()?.ok()?;
                    let resp = &buf[..n];
                    if Self::response_matches(resp, expected_id, &name, 1) {
                        return Some(resp.to_vec());
                    }
                }
            }));
        }

        // Wait for first successful response
        let mut result = None;
        for handle in handles {
            if let Ok(Some(resp)) = handle.await {
                result = Some(resp);
                break;
            }
        }
        drop(permit);
        
        result.ok_or_else(|| AetherError::Other("All DNS queries failed".into()))
    }

    /// Process a DNS query from the TUN
    /// Returns (response_data, is_gemini) where is_gemini indicates if anti-sanction path was used
    pub async fn process_query(&self, packet: &[u8], ihl: usize) -> Option<(Vec<u8>, bool)> {
        if packet.len() < ihl + 8 { return None; }
        let udp = &packet[ihl..];
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        if dst_port != DNS_PORT || udp.len() <= 8 { return None; }

        let payload = &udp[8..];
        if payload.len() < 12 { return None; }

        // Parse question to get domain name
        let mut pos = 12;
        let mut labels = Vec::new();
        loop {
            if pos >= payload.len() { return None; }
            let len = payload[pos];
            if len == 0 { pos += 1; break; }
            if len & 0xC0 == 0xC0 { return None; } // compression in query not expected
            pos += 1;
            if pos + len as usize > payload.len() { return None; }
            labels.push(String::from_utf8_lossy(&payload[pos..pos+len as usize]).to_string());
            pos += len as usize;
        }
        if pos + 4 > payload.len() { return None; }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos+1]]);
        if qtype != 1 { return None; } // Only A records

        let domain = labels.join(".");
        let is_gemini = Self::is_gemini_domain(&domain);

        // Non-Gemini queries are NOT handled here. They must continue through
        // the tunnel's normal path — intercepting every query was the previous
        // build's fatal flaw (it broke all DNS on the device).
        if !is_gemini {
            return None;
        }

        // Build cache key (domain + qtype, without transaction ID)
        let mut cache_key = Vec::new();
        cache_key.extend_from_slice(&[0, 0]); // placeholder for ID
        cache_key.extend_from_slice(&payload[2..]); // everything after ID

        // Check cache first (only for Gemini domains)
        if is_gemini {
            let cached = {
                let cache = self.cache.read();
                cache.get(&cache_key).and_then(|c| {
                    if c.expires > Instant::now() { Some(c.data.clone()) } else { None }
                })
            };
            if let Some(mut resp) = cached {
                // Restore transaction ID from original query
                if resp.len() >= 2 && payload.len() >= 2 {
                    resp[0] = payload[0];
                    resp[1] = payload[1];
                }
                return Some((resp, true));
            }
        }

        // Build fresh query with new transaction ID
        let (query, new_id) = Self::build_query(&domain, qtype);
        let query2 = query.clone();

        // Choose DNS path
        let (response, used_anti_sanction) = if is_gemini {
            // Race anti-sanction servers
            match self.parallel_query(self.anti_sanction_sockets.clone(), query.clone(), new_id, domain.clone()).await {
                Ok(resp) => (resp, true),
                Err(_) => {
                    // Fallback to default DNS
                    match self.parallel_query(self.default_sockets.clone(), query.clone(), new_id, domain.clone()).await {
                        Ok(resp) => (resp, false),
                        Err(_e) => return Some((Self::build_error_response(&query2, new_id), true)),
                    }
                }
            }
        } else {
            // Normal path: default DNS only
            match self.parallel_query(self.default_sockets.clone(), query.clone(), new_id, domain.clone()).await {
                Ok(resp) => (resp, false),
                Err(_) => return Some((Self::build_error_response(&query2, new_id), false)),
            }
        };

        // Cache Gemini responses
        if is_gemini {
            let mut cache = self.cache.write();
            if cache.len() > 1024 { cache.clear(); }
            cache.insert(cache_key, CachedResponse {
                data: response.clone(),
                expires: Instant::now() + CACHE_TTL,
            });
        }

        Some((response, used_anti_sanction))
    }

    /// Build a minimal DNS error response (SERVFAIL)
    fn build_error_response(query: &[u8], id: u16) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[0..2].copy_from_slice(&id.to_be_bytes());
        resp[2] = 0x81; // response + error
        resp[3] = 0x02; // SERVFAIL
        resp
    }
}

/// Global instance holder
static SMART_DNS: once_cell::sync::OnceCell<SmartDnsSplit> = once_cell::sync::OnceCell::new();

/// Initialize the global Smart DNS engine
pub async fn init_smart_dns() -> Result<()> {
    log::info!("[smart-dns] AI Mode ON — standing up Smart DNS Split engine (Gemini-only, {} anti-sanction resolvers)", ANTI_SANCTION_DNS.len());
    let engine = SmartDnsSplit::new().await?;
    SMART_DNS.set(engine).map_err(|_| AetherError::Other("Smart DNS already initialized".into()))?;
    log::info!("[smart-dns] engine ready: pre-connected sockets up, cache live");
    Ok(())
}

/// Get the global Smart DNS engine
pub fn smart_dns() -> Option<&'static SmartDnsSplit> {
    SMART_DNS.get()
}