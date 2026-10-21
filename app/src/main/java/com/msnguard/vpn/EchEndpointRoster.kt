package com.msnguard.vpn

import android.content.Context
import android.util.Base64
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONArray
import org.json.JSONObject

/**
 * ECH lookup roster — automatic fallback, fully cache-first.
 *
 * ## The one surface this widens
 * The main-path WARP identity (AETHER_API_ECH, embedded base64 blob) and every
 * SHARD node's `ech=` share ONE lookup pair: "cloudflare-ech.com+udp://1.1.1.1"
 * (with the embedded-blob copy in CoreConfig / WarpIdentityFetcher, and the
 * domain-resolver form inside the subscription's ech= field resolved by xray).
 * On carriers that now block that exact pair, the identity key can no longer be
 * fetched and every ECH-family node dies. This roster holds all the known-good
 * name+resolver pairs (the same list the user collected in the field, primary
 * first), probes each with a REAL DNS HTTPS(type 65) query and hands out:
 *   - a SHARD-side pair substitution: keep the probe's exact wire format
 *     (nothing in the outbound shape changes, only the pair string);
 *   - a fresh base64 blob for the aether API embed, ONLY from probes whose
 *     domain is cloudflare-ech.com (the blob's public_name must stay the same
 *     as the hardcoded one, so the API SNI camouflage is byte-identical).
 *
 * ## Fail-safes (no regression)
 * Nothing is substituted until the probe has actually VERIFIED a pair against
 * the live network. With no verified pair, every call returns exactly what it
 * got (the old value) — so on carriers where the old pair still works,
 * behavior is unchanged even before a probe cycle completes.
 *
 * + Every probe runs on a daemon thread with a 2.5 s timeout per pair; there
 * is no busy-wait on the connect path and no extra xray/SHARD instance —
 * same room the DNS stack already gets.
 */
object EchEndpointRoster {

    private const val PREF =
        "ech_roster_live" // JSON {verified:[{spec,ech,ts}], freshKey, ts}

    /** Probe results older than this expire and a new cycle is armed. */
    private const val MAX_AGE_MS = 30 * 60_000L
    private const val DNS_PORT = 53
    private const val UDP_TIMEOUT_MS = 2500

    /** Primary pair first (the legacy one) — probing order = fallback order. */
    val CANDIDATES = listOf(
        "cloudflare-ech.com+udp://1.1.1.1",
        "cloudflare-ech.com+https://8.8.8.8/dns-query",
        "crypto.cloudflare.com+udp://1.1.1.1",
        "cloudflare-ech.com+udp://45.90.28.0",
        "cloudflare-ech.com+udp://185.228.168.9",
        "cloudflare-ech.com+udp://64.6.65.6",
        "cloudflare-ech.com+udp://76.76.2.0",
        "miraheze.org+udp://1.1.1.1",
        "tgju.org+udp://1.1.1.1",
        "iranva.ir+udp://1.1.1.1",
        "cloudflare-ech.com+udp://185.228.169.9",
        "ip.gs+udp://1.1.1.1",
    )

    /** The public_name the aether embed and the SHARD ECH family must keep. */
    private const val CF_ECH_DOMAIN = "cloudflare-ech.com"

    private data class Verified(val spec: String, val ech: String, val ts: Long)
    private data class Cache(val verified: List<Verified>, val freshKey: String?, val ts: Long)

    @Volatile private var cache: Cache? = null
    private val probing = AtomicBoolean(false)
    /** "name+resolver" → (name, resolver); null when not the standard shape. */
    private fun parts(spec: String): Pair<String, String>? {
        val i = spec.indexOf('+')
        if (i <= 0 || i >= spec.length - 1) return null
        return spec.substring(0, i) to spec.substring(i + 1)
    }

    // -------------------------------------------------------- read side

    /**
     * A pair for the SHARD outbound builder. Differs from [requested] ONLY
     * when a verified fallback pair exists — same-name pairs are preferred
     * exactly (the outer ECH public name is untouched), verified order is
     * probe order, which keeps the primary candidate noble. On no cache, on
     * an expired cache and on anything not matching the "x+y" shape, the
     * requested value comes back verbatim.
     */
    fun substitutePair(context: Context, requested: String?): String {
        if (requested.isNullOrBlank() || parts(requested) == null) return requested ?: ""
        ensureCache(context)
        val c = cache ?: return requested
        val rqName = parts(requested)!!.first.lowercase()
        // Prefer same outer name (e.g. cloudflare-ech.com with a different
        // resolver). Generic pairs only once every same-name pair is dead.
        val same = c.verified.filter { parts(it.spec)?.first?.lowercase() == rqName }
        val pick = (same.ifEmpty { c.verified }).firstOrNull() ?: return requested
        return if (pick.spec == requested) requested else pick.spec
    }

    /**
     * A fresh base64 blob for AETHER_API_ECH, or null. Only probes whose
     * domain IS cloudflare-ech.com count — the embedded constant's public_name
     * must be preserved byte-for-byte for the api.cloudflareclient.com SNI.
     */
    fun freshApiEch(context: Context): String? {
        ensureCache(context)
        return cache?.freshKey
    }

    /** Arm a probe cycle if the cache is absent/expired. Never blocks. */
    fun maybeProbe(context: Context) {
        ensureCache(context)
        val c = cache
        if (c != null && System.currentTimeMillis() - c.ts < MAX_AGE_MS) return
        if (!probing.compareAndSet(false, true)) return
        Thread({
            try {
                val fresh = runProbe()
                cache = fresh
                persist(context, fresh)
                ConnectionLog.record(
                    "ECH roster: probed " + CANDIDATES.size + " pair(s) → " +
                        (if (fresh.verified.isEmpty()) "none verified (keep legacy)"
                         else fresh.verified.joinToString(" | ") { it.spec })
                )
            } catch (e: Exception) {
                ConnectionLog.record("ECH roster: probe cycle failed — " + (e.message ?: "unknown"))
            } finally {
                probing.set(false)
            }
        }, "ech-roster-probe").apply { isDaemon = true; start() }
    }

    // -------------------------------------------------------- probe engine

    private fun runProbe(): Cache {
        // Probe in candidate order with a small pool so a dead pair never
        // stretches the whole cycle; results arrive in candidate order.
        val results = arrayOfNulls<Verified>(CANDIDATES.size)
        val lanes = java.util.concurrent.Executors.newFixedThreadPool(4)
        val futures = CANDIDATES.indices.map { i ->
            lanes.submit<Verified?> {
                val p = parts(CANDIDATES[i]) ?: return@submit null
                val ech = probePair(p.first, p.second) ?: return@submit null
                Verified(CANDIDATES[i], ech, System.currentTimeMillis())
            }
        }
        lanes.shutdown()
        futures.forEachIndexed { i, f -> try { results[i] = f.get() } catch (_: Exception) {} }
        val verified = results.filterNotNull()
        val freshKey = verified.firstOrNull { parts(it.spec)?.first?.lowercase() == CF_ECH_DOMAIN }?.ech
        return Cache(verified, freshKey, System.currentTimeMillis())
    }

    /** One raw HTTPS(65) DNS exchange for [domain] over [resolver]; returns the ech config list or null. */
    private fun probePair(domain: String, resolver: String): String? = try {
        val query = buildDnsQuery(domain)
        val resp: ByteArray? = when {
            resolver.startsWith("udp://", ignoreCase = true) -> udpExchange(resolver.removePrefix("udp://").trim('/'), query)
            resolver.startsWith("https://", ignoreCase = true) -> dohExchange(resolver, query)
            else -> null
        }
        if (resp == null) null else extractEch(resp)
    } catch (_: Exception) { null }

    private fun udpExchange(hostPort: String, query: ByteArray): ByteArray? {
        val host = hostPort.substringBefore(':').trim()
        val port = hostPort.substringAfter(':', DNS_PORT.toString()).toIntOrNull() ?: DNS_PORT
        if (host.isEmpty()) return null
        return DatagramSocket().use { s ->
            s.soTimeout = UDP_TIMEOUT_MS
            val addr = InetAddress.getByName(host)
            s.send(DatagramPacket(query, query.size, addr, port))
            val buf = ByteArray(4096)
            val pkt = DatagramPacket(buf, buf.size)
            s.receive(pkt)
            buf.copyOf(pkt.length)
        }
    }

    private fun dohExchange(url: String, query: ByteArray): ByteArray? {
        val c = (java.net.URI(url).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = UDP_TIMEOUT_MS
            readTimeout = UDP_TIMEOUT_MS
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/dns-message")
            setRequestProperty("Accept", "application/dns-message")
        }
        c.outputStream.use { it.write(query); it.flush() }
        return try {
            if (c.responseCode !in 200..299) null else c.inputStream.readBytes()
        } finally { c.disconnect() }
    }

    /** Minimal DNS question: TYPE 65 (HTTPS), RD set, fixed id. */
    private fun buildDnsQuery(domain: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(0x1F); out.write(0x2F)             // fixed txn id
        out.write(1)                                 // RD
        out.write(0); out.write(1)                   // QDCOUNT = 1
        out.write(0); out.write(0); out.write(0); out.write(0); out.write(0); out.write(0)
        domain.split('.').forEach { label ->
            val b = label.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0)                                  // root
        out.write(0); out.write(65)                   // QTYPE = HTTPS
        out.write(0); out.write(1)                    // QCLASS = IN
        return out.toByteArray()
    }

    /**
     * Walk the ANSWER section, pull the SvcParam key 5 (ech) payloads out of
     * each HTTPS record (type 65), dedupe, and glue them back together as the
     * base64 form both the engine and xray expect.
     */
    private fun extractEch(resp: ByteArray): String? {
        if (resp.size < 12) return null
        var off = 12
        val qd = ((resp[4].toInt() and 0xFF) shl 8) or (resp[5].toInt() and 0xFF)
        val an = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
        for (i in 0 until qd) {
            off = skipName(resp, off)
            off += 4 // QTYPE + QCLASS
        }
        val found = LinkedHashSet<String>()
        for (i in 0 until an) {
            off = skipName(resp, off)
            if (off + 10 > resp.size) return if (found.isEmpty()) null else found.joinToString("&")
            val type = ((resp[off].toInt() and 0xFF) shl 8) or (resp[off + 1].toInt() and 0xFF)
            val rdLen = ((resp[off + 8].toInt() and 0xFF) shl 8) or (resp[off + 9].toInt() and 0xFF)
            off += 10
            if (type == 65 && rdLen > 4) {
                var r = off
                r += 2                                    // SVCB priority
                r = skipName(resp, r)                     // target domain
                while (r + 4 <= off + rdLen) {
                    val key = ((resp[r].toInt() and 0xFF) shl 8) or (resp[r + 1].toInt() and 0xFF)
                    val len = ((resp[r + 2].toInt() and 0xFF) shl 8) or (resp[r + 3].toInt() and 0xFF)
                    val vStart = r + 4
                    val vEnd = vStart + len
                    if (vEnd > off + rdLen) break
                    if (key == 5 && len > 0) {
                        // The wire value is the raw ECHConfigList — same bytes
                        // the embedded constant base64-encodes; encode here.
                        found.add(Base64.encodeToString(resp.copyOfRange(vStart, vEnd), Base64.NO_WRAP))
                    }
                    r = vEnd
                }
            }
            off += rdLen
        }
        // First record wins — an HTTPS RRSet may repeat, and gluing several
        // config lists together would not parse.
        return found.firstOrNull()
    }

    /** Skip a (possibly compressed) DNS name; returns the byte offset after it. */
    private fun skipName(msg: ByteArray, start: Int): Int {
        var off = start
        while (off < msg.size) {
            val len = msg[off].toInt() and 0xFF
            if (len == 0) return off + 1
            if (len >= 0xC0) return off + 2 // compression pointer terminates the name
            off += len + 1
        }
        return off
    }

    // -------------------------------------------------------- persistence

    private fun ensureCache(context: Context) {
        if (cache != null) return
        synchronized(this) {
            if (cache != null) return
            try {
                val raw = context.profiled().getString(PREF, null) ?: return
                val o = JSONObject(raw)
                val arr = o.optJSONArray("verified") ?: return
                val list = ArrayList<Verified>(arr.length())
                for (i in 0 until arr.length()) {
                    val v = arr.optJSONObject(i) ?: continue
                    val spec = v.optString("spec")
                    val ech = v.optString("ech")
                    if (spec.isNotEmpty() && ech.isNotEmpty()) list.add(Verified(spec, ech, v.optLong("ts")))
                }
                if (list.isEmpty()) return
                val freshKey = list.firstOrNull { parts(it.spec)?.first?.lowercase() == CF_ECH_DOMAIN }?.ech
                cache = Cache(list, freshKey, o.optLong("ts"))
            } catch (_: Exception) {}
        }
    }

    private fun persist(context: Context, c: Cache) {
        try {
            val arr = JSONArray()
            c.verified.forEach { v -> arr.put(JSONObject().put("spec", v.spec).put("ech", v.ech).put("ts", v.ts)) }
            context.profiled().edit().putString(PREF, JSONObject().put("verified", arr).put("ts", c.ts).toString()).commit()
        } catch (_: Exception) {}
    }
}
