package com.msnguard.vpn

import android.content.Context
import com.msnguard.vpn.shard.toShardNode
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Xray sidecar for MASQUE/MIM exit only (Warp Setting).
 * Isolated from SHARD: own port (1826), own process, own config dir.
 * Used only when currentProtocol in {masque,mim} and warpExitIsCustom.
 * Chain: aether --upstream socks5://127.0.0.1:1826 --> xray SOCKS 1826 --> user's
 * tunnel (gRPC/ws/etc) --> exit. Accepted link types: vless, vmess, trojan,
 * shadowsocks (SIP002 + legacy), socks://, socks5://, hysteria2:// — wireguard,
 * anytls and everything else parse≠null-compatible are rejected up front.
 */
object WarpExitManager {
    private const val TAG = "WarpExit"
    const val SOCKS_PORT = 1826
    private val running = AtomicBoolean(false)
    @Volatile private var process: Process? = null
    @Volatile private var logThread: Thread? = null
    @Volatile var activeLabel: String = ""
        private set
    @Volatile private var activeUrl: String = ""
    @Volatile var pendingWarpAttach: Boolean = false
        private set
    @Volatile var lastError: String = ""
        private set
    val isRunning: Boolean get() = running.get() && process?.isAlive == true

    /** Rebuild the same Exit config after WARP's own SOCKS listener is ready. */
    fun attachToWarp(context: Context, dialViaPort: Int): Boolean {
        val url = activeUrl
        if (url.isBlank()) return false
        val ok = start(context, url, dialViaPort)
        if (!ok) return false
        // Do not hand the listener to tun2socks until the rebuilt Xray
        // outbound has completed a real TCP dial through WARP.
        val deadline = android.os.SystemClock.elapsedRealtime() + 12_000L
        var tcpOk = false
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            if (probeTcpThroughExit("www.cloudflare.com", 443, 2_000)) {
                tcpOk = true
                break
            }
            try { Thread.sleep(250) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
        }
        if (!tcpOk) {
            lastError = "Exit outbound did not pass TCP preflight after WARP attach"
            ConnectionLog.record("$TAG attach TCP preflight failed; refusing to expose Exit")
            stopAndWait()
            return false
        }
        pendingWarpAttach = false
        return true
    }

    private fun binary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, "libxray.so")

    private fun launch(context: Context, configFile: File): Boolean {
        val bin = binary(context)
        if (!bin.exists()) {
            lastError = "xray binary missing"
            ConnectionLog.record("$TAG binary missing at ${bin.absolutePath}")
            return false
        }
        val pb = ProcessBuilder(bin.absolutePath, "run", "-c", configFile.absolutePath)
        pb.directory(configFile.parentFile)
        pb.redirectErrorStream(true)
        pb.environment()["HOME"] = context.filesDir.absolutePath
        pb.environment()["XRAY_LOCATION_ASSET"] = configFile.parent
        val p = try { pb.start() } catch (e: Exception) {
            lastError = "could not start xray: ${e.message}"
            ConnectionLog.record("$TAG exec failed: ${e.message}")
            return false
        }
        process = p
        logThread = Thread({
            try {
                BufferedReader(InputStreamReader(p.inputStream)).forEachLine { line ->
                    if (line.isNotBlank() && !isNoise(line)) ConnectionLog.record("$TAG $line")
                }
            } catch (_: Exception) {}
        }, "warpexit-log").apply { isDaemon = true; start() }
        return true
    }

    private fun isNoise(line: String): Boolean =
        line.contains("is deprecated, not recommended") ||
        line.contains("deprecated, will be removed soon") ||
        line.contains("[in >> proxy]") ||
        line.contains("A unified platform for anti-censorship") ||
        line.contains("infra/conf/serial: Reading config")

    private fun stopAndWait(clearConfig: Boolean = true) {
        running.set(false)
        if (clearConfig) {
            activeLabel = ""
            activeUrl = ""
            pendingWarpAttach = false
        }
        val proc = process
        process = null
        logThread = null
        try { proc?.destroy() } catch (_: Exception) {}
        try {
            if (proc != null && proc.isAlive && !proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                proc.destroyForcibly()
                proc.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)
            }
        } catch (_: Exception) {}
        running.set(false)
    }

    fun stop() = stopAndWait()

    /**
     * Matches the reference client's stage-1 gate: prove that the sidecar can
     * carry a real outbound TCP connection before Aether is started. A listener
     * on localhost only proves that Xray booted; it says nothing about the
     * selected Exit Node's upstream path.
     */
    fun probeTcpThroughExit(host: String, port: Int, timeoutMs: Int = 8_000): Boolean {
        if (!isRunning) return false
        return runCatching {
            val proxy = java.net.Proxy(
                java.net.Proxy.Type.SOCKS,
                InetSocketAddress("127.0.0.1", SOCKS_PORT),
            )
            java.net.Socket(proxy).use { socket ->
                socket.connect(InetSocketAddress.createUnresolved(host, port), timeoutMs)
                socket.isConnected && !socket.isClosed
            }
        }.onFailure {
            ConnectionLog.record("$TAG upstream TCP preflight failed: ${it.javaClass.simpleName}: ${it.message ?: "unknown"}")
        }.getOrDefault(false)
    }

    /**
     * Reads Cloudflare's authenticated trace response through one local SOCKS hop.
     * The result identifies the egress of that listener; it never logs the VLESS
     * link or any credential.
     */
    fun probeCloudflareTrace(socksPort: Int, label: String, timeoutMs: Int = 8_000): Boolean {
        return runCatching {
            val connection = java.net.URL("https://www.cloudflare.com/cdn-cgi/trace")
                .openConnection(
                    java.net.Proxy(
                        java.net.Proxy.Type.SOCKS,
                        InetSocketAddress("127.0.0.1", socksPort),
                    )
                ) as java.net.HttpURLConnection
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.requestMethod = "GET"
            try {
                check(connection.responseCode in 200..399) { "HTTP ${connection.responseCode}" }
                val fields = connection.inputStream.bufferedReader().use { reader ->
                    reader.readLines().mapNotNull { line ->
                        line.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] }
                    }.toMap()
                }
                val ip = fields["ip"].orEmpty()
                val loc = fields["loc"].orEmpty()
                check(ip.isNotBlank()) { "trace did not return ip" }
                ConnectionLog.record("$TAG route probe=$label listener=127.0.0.1:$socksPort egressIp=$ip cfLoc=${loc.ifBlank { "unknown" }}")
                true
            } finally {
                connection.disconnect()
            }
        }.onFailure {
            ConnectionLog.record("$TAG route probe=$label listener=127.0.0.1:$socksPort failed=${it.javaClass.simpleName}")
        }.getOrDefault(false)
    }

    fun start(
        context: Context,
        exitUrl: String,
        dialViaPort: Int? = CoreConfig.SOCKS_PORT,
        reverseChain: Boolean = false,
    ): Boolean {
        val keepUrl = exitUrl
        stop()
        activeUrl = keepUrl
        // A null upstream means the sidecar is staged first and attached only
        // after WARP has published its SOCKS listener. This breaks the startup
        // cycle without changing the Direct path.
        // Reverse chain keeps the sidecar stable as WARP's upstream. It must not
        // be rebuilt after WARP starts: that would turn WARP -> VLESS back into
        // VLESS -> WARP.
        pendingWarpAttach = dialViaPort == null && !reverseChain
        if (reverseChain) {
            ConnectionLog.record("$TAG mode=Warp Over V2ray; inbound=127.0.0.1:$SOCKS_PORT udp=true outbound=custom")
        }
        lastError = ""
        activeLabel = keepUrl.take(48)
        val node = parseExitNode(exitUrl)
        if (node == null) {
            lastError = "could not parse config — supported: vless, vmess, trojan, ss, socks, hysteria2 (one link)"
            ConnectionLog.record("$TAG parse failed for ${exitUrl.take(80)}")
            return false
        }
        val listenHost = "127.0.0.1"
        val port = SOCKS_PORT
        val logLevel = "warning"
        val config = ShardConfigs.tunnelConfig(context, node, listenHost, port, logLevel, dialViaPort = dialViaPort, reverseChain = reverseChain)
        val configFile = ShardConfigs.writeConfig(context, "warpexit.json", config)
        if (!launch(context, configFile)) return false
        if (awaitListener(port, timeoutMs = 8000)) {
            running.set(true)
            ConnectionLog.record("$TAG up on $port via ${LogRedactor.nodeTag(node.key)}")
            if (reverseChain) {
                val deadline = android.os.SystemClock.elapsedRealtime() + 12_000L
                var tcpOk = false
                while (android.os.SystemClock.elapsedRealtime() < deadline) {
                    if (probeTcpThroughExit("www.cloudflare.com", 443, 2_000)) {
                        tcpOk = true
                        break
                    }
                    try { Thread.sleep(250) } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        break
                    }
                }
                if (!tcpOk) {
                    lastError = "reverse Exit outbound did not pass TCP preflight"
                    ConnectionLog.record("$TAG reverse-chain TCP preflight failed; refusing Warp Over V2ray")
                    stopAndWait()
                    return false
                }
                ConnectionLog.record("$TAG reverse-chain TCP preflight passed")
            }
            return true
        }
        lastError = "listener $port never came up"
        ConnectionLog.record("$TAG port $port never opened")
        stop()
        return false
    }

    /** One link → one node, bypassing the SHARD subscription pool parser
     *  (which deliberately skips vmess). Everything the sidecar core really
     *  renders goes through [com.msnguard.vpn.shard.ShardImport.parseOne];
     *  vmess gets its own [VmessFmt] (base64-JSON share link). */
    private fun parseExitNode(raw: String): ShardNode? {
        val line = raw.trim().lines().firstOrNull { it.isNotBlank() && !it.startsWith("#") } ?: return null
        val profile = (if (line.startsWith("vmess://", ignoreCase = true))
            com.msnguard.vpn.shard.VmessFmt.parse(line)
            else com.msnguard.vpn.shard.ShardImport.parseOne(line)) ?: return null
        val parsed = profile.toShardNode()
        // URI IPv6 hosts are written as [addr] so the port is unambiguous.
        // Xray's server field expects the bare literal; keeping the brackets
        // makes the sidecar treat the host as malformed and closes the pipe.
        // URI.idnHost() already removes IPv6 brackets. Keep the bare literal:
        // Xray's JSON server.address wants `2606:...`, while the URI only uses
        // brackets to delimit the host from its port.
        val node = parsed.copy(address = parsed.address.removeSurrounding("[", "]"))
        if (node.address.isBlank() || node.port !in 1..65535) return null
        return node
    }

    private fun awaitListener(port: Int, timeoutMs: Long): Boolean {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            if (process?.isAlive != true) return false
            try {
                Socket().use { s -> s.connect(InetSocketAddress("127.0.0.1", port), 400); return true }
            } catch (_: Exception) {}
            try { Thread.sleep(200) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); return false }
        }
        return false
    }
}
