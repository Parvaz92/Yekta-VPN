package com.msnguard.vpn

import android.content.Context
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Smart DNS Split Engine for Gemini domains.
 *
 * Intercepts DNS queries on the device and routes them based on domain:
 * - Gemini domains → Parallel query to anti-sanction DNS servers (403.online, Electro, Shecan)
 * - Other domains → Default public DNS (Cloudflare 1.1.1.1, Google 8.8.8.8)
 *
 * Uses Plain UDP (port 53) for maximum speed, no DoT/DoH overhead.
 * In-memory cache provides 0ms response for repeated Gemini queries.
 */
class SmartDnsSplit private constructor(context: Context) {

    companion object {
        private const val TAG = "SmartDnsSplit"
        private const val LOCAL_DNS_PORT = 15353  // Local port for our DNS server
        private const val CACHE_TTL_MS = 300_000L  // 5 minutes TTL for cache
        private const val QUERY_TIMEOUT_MS = 2000L  // Timeout for upstream queries
        private const val PARALLEL_QUERY_DELAY_MS = 50L  // Stagger parallel queries slightly

        // Gemini domains that need anti-sanction routing
        private val GEMINI_DOMAINS = setOf(
            "gemini.google.com",
            "generativelanguage.googleapis.com",
            "alkalinetransmit-pa.googleapis.com",
            "bard.google.com",
            "proactivity-pa.googleapis.com"
        )

        // Anti-sanction DNS servers (Plain UDP, port 53)
        private val ANTI_SANCTION_DNS = listOf(
            // 403.online
            "10.202.10.202",
            "10.202.10.102",
            // Electro
            "78.157.42.100",
            "78.157.42.101",
            // Shecan
            "178.22.122.100",
            "185.51.200.2"
        )

        // Default fast DNS for non-Gemini traffic
        private val DEFAULT_DNS = listOf(
            "1.1.1.1",
            "8.8.8.8",
            "1.0.0.1",
            "8.8.4.4"
        )

        @Volatile private var instance: SmartDnsSplit? = null
        private val lock = Any()

        fun getInstance(context: Context): SmartDnsSplit {
            var inst = instance
            if (inst == null) {
                synchronized(lock) {
                    inst = instance
                    if (inst == null) {
                        inst = SmartDnsSplit(context.applicationContext)
                        instance = inst
                    }
                }
            }
            return inst!!
        }

        fun isGeminiDomain(domain: String): Boolean {
            val normalized = domain.lowercase().trimEnd('.')
            return GEMINI_DOMAINS.any { normalized == it || normalized.endsWith(".$it") }
        }

        fun getLocalDnsAddress(): InetSocketAddress {
            return InetSocketAddress("127.0.0.1", LOCAL_DNS_PORT)
        }
    }

    // In-memory cache: domain -> (ip, expiryTime)
    private val dnsCache = ConcurrentHashMap<String, CacheEntry>()
    private val executor = Executors.newSingleThreadExecutor()
    private val queryExecutor = Executors.newFixedThreadPool(8)
    private val scheduledExecutor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val serverSocket: DatagramSocket? by lazy { createServerSocket() }
    private val running = AtomicBoolean(false)
    private val queryId = AtomicInteger(0)
    private val pendingQueries = ConcurrentHashMap<Int, PendingQuery>()

    private data class CacheEntry(val ip: String, val expiry: Long)
    private data class PendingQuery(
        val clientAddr: InetSocketAddress,
        val queryBytes: ByteArray,
        val domain: String,
        val startTime: Long
    )

    private fun createServerSocket(): DatagramSocket? {
        return try {
            val socket = DatagramSocket(LOCAL_DNS_PORT, InetAddress.getByName("127.0.0.1"))
            socket.soTimeout = 100 // Short timeout for responsive shutdown
            socket
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create DNS server socket", e)
            null
        }
    }

    /** Starts the local DNS server. */
    fun start() {
        if (running.getAndSet(true)) return
        executor.execute { runServer() }
        // Periodic cache cleanup
        scheduledExecutor.scheduleAtFixedRate({ cleanupCache() }, CACHE_TTL_MS, CACHE_TTL_MS, TimeUnit.MILLISECONDS)
        Log.i(TAG, "Smart DNS Split started on 127.0.0.1:$LOCAL_DNS_PORT")
    }

    /** Stops the local DNS server. */
    fun stop() {
        if (!running.getAndSet(false)) return
        serverSocket?.close()
        executor.shutdownNow()
        queryExecutor.shutdownNow()
        scheduledExecutor.shutdownNow()
        dnsCache.clear()
        pendingQueries.clear()
        Log.i(TAG, "Smart DNS Split stopped")
    }

    private fun runServer() {
        val buffer = ByteArray(512)
        val packet = DatagramPacket(buffer, buffer.size)
        while (running.get()) {
            try {
                serverSocket?.receive(packet)
                if (!running.get()) break
                handleQuery(packet)
            } catch (e: java.net.SocketTimeoutException) {
                // Expected - just loop
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "DNS server error", e)
            }
        }
    }

    private fun handleQuery(packet: DatagramPacket) {
        val queryBytes = packet.data.copyOfRange(0, packet.length)
        val domain = extractDomain(queryBytes)
        if (domain.isNullOrEmpty()) {
            // Forward to default DNS if we can't parse
            forwardToDefault(packet)
            return
        }

        val isGemini = SmartDnsSplit.isGeminiDomain(domain)

        // Check cache first
        val cached = dnsCache[domain]
        if (cached != null && cached.expiry > System.currentTimeMillis()) {
            sendCachedResponse(packet, domain, cached.ip)
            return
        }

        if (isGemini) {
            // Parallel query to anti-sanction DNS servers
            queryAntiSanctionParallel(packet, domain, queryBytes)
        } else {
            // Default DNS for other domains
            forwardToDefault(packet)
        }
    }

    private fun extractDomain(queryBytes: ByteArray): String? {
        return try {
            // Simple DNS query parsing - extract domain name from question section
            var pos = 12 // Skip header
            val labels = mutableListOf<String>()
            while (pos < queryBytes.size) {
                val len = queryBytes[pos].toInt() and 0xFF
                if (len == 0) break
                if ((len and 0xC0) == 0xC0) break // Compression pointer - simplified
                val label = String(queryBytes.copyOfRange(pos + 1, pos + 1 + len))
                labels.add(label)
                pos += 1 + len
            }
            if (labels.isEmpty()) return null
            labels.joinToString(".")
        } catch (e: Exception) {
            null
        }
    }

    private fun sendCachedResponse(originalPacket: DatagramPacket, domain: String, ip: String) {
        // Build DNS response with cached IP
        val response = buildDnsResponse(originalPacket.data.copyOfRange(0, originalPacket.length), domain, ip)
        val replyPacket = DatagramPacket(response, response.size, originalPacket.socketAddress)
        try {
            serverSocket?.send(replyPacket)
            Log.d(TAG, "Cache hit for $domain -> $ip (0ms)")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to send cached response", e)
        }
    }

    private fun queryAntiSanctionParallel(
        originalPacket: DatagramPacket,
        domain: String,
        queryBytes: ByteArray
    ) {
        val queryId = this.queryId.incrementAndGet()
        val pending = PendingQuery(
            clientAddr = originalPacket.socketAddress as InetSocketAddress,
            queryBytes = queryBytes,
            domain = domain,
            startTime = System.currentTimeMillis()
        )
        pendingQueries[queryId] = pending

        // Query all anti-sanction DNS servers in parallel
        for ((index, dnsIp) in ANTI_SANCTION_DNS.withIndex()) {
            queryExecutor.execute {
                // Small stagger to avoid thundering herd
                if (index > 0) Thread.sleep(PARALLEL_QUERY_DELAY_MS.toLong())
                queryUpstream(queryId, dnsIp, queryBytes)
            }
        }

        // Timeout handler - if no response in time, fall back to default
        executor.execute {
            Thread.sleep(QUERY_TIMEOUT_MS)
            val p = pendingQueries.remove(queryId)
            if (p != null) {
                // No response received, forward to default DNS
                forwardToDefault(originalPacket)
            }
        }
    }

    private fun queryUpstream(queryId: Int, dnsIp: String, queryBytes: ByteArray) {
        val pending = pendingQueries[queryId] ?: return
        try {
            val socket = DatagramSocket()
            socket.soTimeout = QUERY_TIMEOUT_MS.toInt()
            val serverAddr = InetSocketAddress(dnsIp, 53)
            val packet = DatagramPacket(queryBytes, queryBytes.size, serverAddr)
            socket.send(packet)

            val responseBuffer = ByteArray(512)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            socket.close()

            // Parse response to get IP
            val ip = extractIpFromResponse(responsePacket.data.copyOfRange(0, responsePacket.length))
            if (ip != null) {
                // Check if this query is still pending (first response wins)
                val p = pendingQueries.remove(queryId)
                if (p != null) {
                    // Cache the result
                    cacheResult(p.domain, ip)
                    // Send response to client
                    val response = buildDnsResponse(p.queryBytes, p.domain, ip)
                    val replyPacket = DatagramPacket(response, response.size, p.clientAddr)
                    serverSocket?.send(replyPacket)
                    val latency = System.currentTimeMillis() - p.startTime
                    Log.d(TAG, "Anti-sanction DNS $dnsIp answered for ${p.domain} -> $ip (${latency}ms)")
                }
            }
        } catch (e: Exception) {
            // Ignore - other servers may respond
        }
    }

    private fun forwardToDefault(packet: DatagramPacket) {
        val queryBytes = packet.data.copyOfRange(0, packet.length)
        val domain = extractDomain(queryBytes) ?: "unknown"

        queryExecutor.execute {
            for (dnsIp in DEFAULT_DNS) {
                try {
                    val socket = DatagramSocket()
                    socket.soTimeout = QUERY_TIMEOUT_MS.toInt()
                    val serverAddr = InetSocketAddress(dnsIp, 53)
                    val queryPacket = DatagramPacket(queryBytes, queryBytes.size, serverAddr)
                    socket.send(queryPacket)

                    val responseBuffer = ByteArray(512)
                    val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                    socket.receive(responsePacket)
                    socket.close()

                    // Forward response to client
                    val replyPacket = DatagramPacket(
                        responsePacket.data.copyOfRange(0, responsePacket.length),
                        responsePacket.length,
                        packet.socketAddress
                    )
                    serverSocket?.send(replyPacket)

                    val ip = extractIpFromResponse(responsePacket.data.copyOfRange(0, responsePacket.length))
                    if (ip != null) {
                        cacheResult(domain, ip)
                    }
                    return@execute
                } catch (e: Exception) {
                    // Try next DNS
                }
            }
            Log.w(TAG, "All default DNS servers failed for $domain")
        }
    }

    private fun extractIpFromResponse(responseBytes: ByteArray): String? {
        return try {
            // Simplified DNS response parsing - find A record in answer section
            var pos = 12 // Skip header
            // Skip questions
            val qdCount = ((responseBytes[4].toInt() and 0xFF) shl 8) or (responseBytes[5].toInt() and 0xFF)
            var i = 0
            while (i < qdCount) {
                while (pos < responseBytes.size && responseBytes[pos].toInt() != 0) {
                    val len = responseBytes[pos].toInt() and 0xFF
                    if ((len and 0xC0) == 0xC0) { pos += 2; break }
                    pos += 1 + len
                }
                pos += 5 // Skip null byte + QTYPE + QCLASS
                i++
            }

            // Parse answers
            val anCount = ((responseBytes[6].toInt() and 0xFF) shl 8) or (responseBytes[7].toInt() and 0xFF)
            var j = 0
            while (j < anCount) {
                if (pos >= responseBytes.size) break
                // Skip name (may be compressed)
                if ((responseBytes[pos].toInt() and 0xC0) == 0xC0) pos += 2 else {
                    while (pos < responseBytes.size && responseBytes[pos].toInt() != 0) {
                        val len = responseBytes[pos].toInt() and 0xFF
                        pos += 1 + len
                    }
                    pos += 1
                }
                if (pos + 10 > responseBytes.size) break
                val type = ((responseBytes[pos].toInt() and 0xFF) shl 8) or (responseBytes[pos + 1].toInt() and 0xFF)
                val rdLength = ((responseBytes[pos + 8].toInt() and 0xFF) shl 8) or (responseBytes[pos + 9].toInt() and 0xFF)
                pos += 10
                if (type == 1 && rdLength == 4) { // A record
                    val ipBytes = responseBytes.copyOfRange(pos, pos + 4)
                    return ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                pos += rdLength
                j++
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun buildDnsResponse(queryBytes: ByteArray, domain: String, ip: String): ByteArray {
        // Build a minimal DNS response with the answer
        val ipBytes = ip.split(".").map { it.toInt().toByte() }.toByteArray()
        val response = ByteArray(queryBytes.size + 16) // Extra space for answer
        System.arraycopy(queryBytes, 0, response, 0, queryBytes.size)

        // Modify header: QR=1, AA=1, RA=1, RCODE=0
        response[2] = (response[2].toInt() or 0x80).toByte() // QR=1
        response[2] = (response[2].toInt() or 0x04).toByte() // AA=1
        response[3] = (response[3].toInt() or 0x80).toByte() // RA=1
        // ANCOUNT = 1
        response[6] = 0
        response[7] = 1

        // Answer section starts after question
        var pos = 12
        while (pos < queryBytes.size && queryBytes[pos].toInt() != 0) {
            val len = queryBytes[pos].toInt() and 0xFF
            if ((len and 0xC0) == 0xC0) { pos += 2; break }
            pos += 1 + len
        }
        pos += 5 // Skip null + QTYPE + QCLASS

        // Write answer: name (pointer to question), type A, class IN, TTL, RDLENGTH, RDATA
        response[pos] = 0xC0.toByte() // Pointer
        response[pos + 1] = 0x0C.toByte() // To offset 12 (start of question name)
        pos += 2
        // TYPE A = 1
        response[pos] = 0; response[pos + 1] = 1; pos += 2
        // CLASS IN = 1
        response[pos] = 0; response[pos + 1] = 1; pos += 2
        // TTL = 300 (5 min)
        response[pos] = 0; response[pos + 1] = 0; response[pos + 2] = 1; response[pos + 3] = 44; pos += 4
        // RDLENGTH = 4
        response[pos] = 0; response[pos + 1] = 4; pos += 2
        // RDATA (IP)
        System.arraycopy(ipBytes, 0, response, pos, 4)

        return response.copyOf(pos + 4)
    }

    private fun cacheResult(domain: String, ip: String) {
        val expiry = System.currentTimeMillis() + CACHE_TTL_MS
        dnsCache[domain] = CacheEntry(ip, expiry)
    }

    private fun cleanupCache() {
        val now = System.currentTimeMillis()
        dnsCache.entries.removeIf { (_, entry) -> entry.expiry <= now }
    }

    /** Gets the local DNS address to configure in TUN. */
    fun getLocalDnsAddress(): InetSocketAddress {
        return SmartDnsSplit.getLocalDnsAddress()
    }

    /** Checks if AI Mode is enabled (for toggleable protocols). */
    fun isAiModeEnabled(context: Context): Boolean {
        return context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean("ai_mode_enabled", false)
    }
}