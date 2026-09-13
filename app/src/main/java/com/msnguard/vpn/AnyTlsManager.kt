package com.msnguard.vpn

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONArray
import org.json.JSONObject

/**
 * The AnyTLS engine: launches the sidecar binary that speaks the AnyTLS
 * protocol ([anytls/cmd/anytls-client]), for probe and live phases.
 *
 * This is an ENGINE, not a transport: which node to use, the pool, the
 * ranking and the race are all decided by [ShardManager], which treats xray
 * nodes and anytls nodes as candidates of one pool. This class only knows
 * how to turn a list of anytls nodes into listeners and keep the process
 * alive — deliberately the same role libxray.so plays, expressed as a
 * process wrapper with the same launch/stop discipline [ShardManager]
 * already proved for xray.
 *
 * ## Shape of an anytls session
 *
 * ```
 *   TUN ─► tun2socks ─► ShardSocksFront 1825 ─► libanytls.so SOCKS 1826 ─► AnyTLS node ─► exit
 *              └─ UDP + DNS ─► same listener (uot: UDP-over-TCP inside the session)
 * ```
 *
 * [ShardSocksFront] is reused verbatim: it only knows about a SOCKS port
 * with UDP ASSOCIATE, which the sidecar provides through uot — verified
 * against a real server before this class was written (associate granted,
 * a DNS query answered through the tunnel). That is what lets the protocol
 * ride the whole existing stack — VPN mode, split tunnelling, the kill
 * switch, the traffic counters — with no new plumbing.
 *
 * ## Why a sidecar executable at all
 *
 * Xray has no AnyTLS outbound (measured against the pinned binary; it is a
 * sing-box-only protocol). A gomobile libcore AAR cannot ship beside the
 * Psiphon AAR — duplicate libgojni.so and go.Seq classes collide — so a
 * second engine arrives the same way tor and xray did: as a PIE executable
 * in jniLibs, launched with ProcessBuilder, never dlopen'd. ~3 MB per ABI
 * against ~25 MB for a full sing-box.
 *
 * ## TLS verification
 *
 * The reference sample client hardcodes InsecureSkipVerify=true, which
 * would make every node MITM-able by the carrier — the exact threat this
 * transport exists to defeat. The sidecar verifies against the Android
 * system trust store (Go reads /system/etc/security/cacerts on its own),
 * and insecure mode stays opt-in per node from the node's own URL
 * (`insecure=1`), carried in [ShardNode.security] as "insecure". Free
 * anytls nodes do routinely use self-signed certs, so the opt-in exists —
 * but it is the node's claim, never our default.
 */
object AnyTlsManager {

    private const val TAG = "AnyTls"

    /**
     * The live tunnel's SOCKS port.
     *
     * Chosen clear of every port already claimed in this app: 1819 core,
     * 1820 chain, 1821-1823 Tor, 1824 xray, 1825 the SHARD front-end.
     */
    const val SOCKS_PORT = 1826

    private val running = AtomicBoolean(false)

    @Volatile
    private var stopRequested = false

    @Volatile
    private var process: Process? = null

    @Volatile
    private var logThread: Thread? = null

    @Volatile
    var lastError: String = ""
        private set

    val isRunning: Boolean
        get() = running.get() && process?.isAlive == true

    /** The port the live listener is bound on; set by [launchLive]. */
    @Volatile
    var listenPort: Int = 0
        private set

    private fun binary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, "libanytls.so")

    /**
     * Launch the sidecar with [configFile].
     *
     * HOME is pointed at the app's private dir so the Go runtime never
     * probes /sdcard paths it cannot read — the same guard xray gets.
     */
    private fun launch(context: Context, configFile: File, tag: String): Boolean {
        val bin = binary(context)
        if (!bin.exists()) {
            lastError = "anytls binary missing"
            ConnectionLog.record("$TAG binary missing at ${bin.absolutePath}")
            return false
        }
        val builder = ProcessBuilder(bin.absolutePath, "-c", configFile.absolutePath)
        builder.directory(configFile.parentFile)
        builder.redirectErrorStream(true)
        builder.environment()["HOME"] = context.filesDir.absolutePath

        val started = try {
            builder.start()
        } catch (e: Exception) {
            lastError = "could not start anytls: ${e.message}"
            ConnectionLog.record("$TAG exec failed: ${e.message}")
            return false
        }
        process = started

        // Drain stdout whatever the level: a child whose pipe fills blocks
        // in write() and stops forwarding traffic — a silent stall. Startup
        // banner lines are dropped; everything else is recorded.
        logThread = Thread({
            try {
                BufferedReader(InputStreamReader(started.inputStream)).forEachLine { line ->
                    if (line.isNotBlank() && !isNoise(line)) ConnectionLog.record("$tag $line")
                }
            } catch (_: Exception) {
            }
        }, "anytls-log").apply { isDaemon = true }.also { it.start() }
        return true
    }

    /**
     * Sidecar output that is noise by construction: the version banner and
     * the per-listener startup lines say nothing about this session.
     */
    private fun isNoise(line: String): Boolean =
        line.contains("[Client] anytls/") ||
            line.contains("[Client] started") ||
            (line.contains("[Client] socks5/http") && line.contains("=>"))

    /**
     * Kill the probe process without latching the cancel flag.
     *
     * stop() latches [stopRequested] for the orchestrator's sake; probe
     * teardown must not, because a successful slice is immediately followed
     * by the live launch.
     */
    fun killProbe() {
        process?.let { proc ->
            try {
                proc.destroy()
                if (!proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    proc.destroyForcibly()
                }
            } catch (_: Exception) {
            }
        }
        if (process != null) {
            process = null
            logThread = null
        }
    }

    /**
     * Stop the engine and forget the session.
     *
     * The latch-then-capture-then-wait-off-thread sequence is
     * [ShardManager.stop]'s, for the same reason: a Disconnect during a
     * connect must never park the MAIN thread on a 3 s waitFor.
     */
    fun stop() {
        stopRequested = true
        val proc = process
        try {
            proc?.destroy()
        } catch (_: Exception) {
        }
        Thread({
            try {
                if (proc != null && proc.isAlive &&
                    !proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
                ) {
                    proc.destroyForcibly()
                }
            } catch (_: Exception) {
            }
            if (process === proc) {
                process = null
                logThread = null
            }
            running.set(false)
        }, "anytls-stop").start()
    }

    /** Clear a stale latch so the next connect is not poisoned by the last stop. */
    fun armForStart() {
        stopRequested = false
        lastError = ""
    }

    val cancelRequested: Boolean get() = stopRequested

    /**
     * Bring the live tunnel up on [port] with exactly [node].
     *
     * Called by [ShardManager] after a race this engine won. The listener
     * host follows the LAN-sharing setting exactly as xray's does.
     *
     * @return true when the sidecar is up and its listener accepts.
     */
    fun launchLive(
        context: Context,
        node: ShardNode,
        listenHost: String,
        port: Int,
        verboseLog: Boolean,
    ): Boolean {
        armForStart()
        val config = renderConfig(
            listOf(node),
            listenHost,
            port,
            httpListen = if (listenHost != "127.0.0.1") CoreConfig.HTTP_PROXY_PORT else null,
            verbose = verboseLog,
        )
        val configFile = writeConfig(context, "anytls-tunnel.json", config)
        if (stopRequested) return false
        if (!launch(context, configFile, TAG)) return false
        if (awaitListener(port)) {
            running.set(true)
            listenPort = port
            ConnectionLog.record("$TAG up on $port via ${LogRedactor.nodeTag(node.key)}")
            return true
        }
        lastError = "tunnel listener never came up"
        ConnectionLog.record("$TAG tunnel port $port never opened")
        stop()
        return false
    }

    /**
     * Start the probe phase for [nodes], one listener per node.
     *
     * The port each node gets is decided by the ORCHESTRATOR
     * ([ShardManager.race]) so the two engines' probe ports share one
     * collision-free index space — [probePorts] maps node → port. Returns
     * false when the process cannot start or its first listener never binds;
     * individual nodes' probes are then simply all-dead, which the race
     * records as failures.
     */
    fun launchProbe(
        context: Context,
        nodes: List<ShardNode>,
        probePorts: Map<ShardNode, Int>,
    ): Boolean {
        val config = renderConfig(nodes, "127.0.0.1", 0, httpListen = null, verbose = false,
            perNodePorts = probePorts)
        val configFile = writeConfig(context, "anytls-probe.json", config)
        return launch(context, configFile, "$TAG/probe")
    }

    private fun portAccepts(port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
            true
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Block until [port] accepts, the process dies, or 6 s pass.
     */
    private fun awaitListener(port: Int): Boolean {
        val deadline = System.currentTimeMillis() + 6000
        while (System.currentTimeMillis() < deadline) {
            if (portAccepts(port, 400)) return true
            if (process?.isAlive != true) return false
            Thread.sleep(120)
        }
        return false
    }

    // ------------------------------------------------------------- config

    /**
     * Render the sidecar's config file.
     *
     * Field names must match anytls/cmd/anytls-client/main.go's structs
     * exactly — they are this class's wire format to the child process.
     *
     * @param perNodePorts overrides the port assignment for the probe
     *   phase, where ports come from the orchestrator's combined index
     *   space rather than a contiguous block.
     */
    private fun renderConfig(
        nodes: List<ShardNode>,
        listenHost: String,
        listenPort: Int,
        httpListen: Int?,
        verbose: Boolean,
        perNodePorts: Map<ShardNode, Int>? = null,
    ): String {
        val arr = JSONArray()
        nodes.forEach { node ->
            val port = perNodePorts?.get(node) ?: listenPort
            arr.put(
                JSONObject().apply {
                    put("listen", "$listenHost:$port")
                    put("server", "${node.address}:${node.port}")
                    put("password", node.credential)
                    if (node.serverName.isNotBlank()) put("sni", node.serverName)
                    // "insecure" travels in ShardNode.security from the
                    // node's own URL — opt-in, never defaulted. See the
                    // class doc.
                    put("insecure", node.security == "insecure")
                    put("min_idle_session", 5)
                }
            )
        }
        return JSONObject().apply {
            put("log_level", if (verbose) "info" else "warn")
            if (httpListen != null) {
                // LAN sharing: the same SOCKS+HTTP pair xray publishes, on
                // the same two ports, so the address the Settings screen
                // prints stays true for this engine too.
                put("http_listen", "$listenHost:$httpListen")
            }
            put("servers", arr)
        }.toString()
    }

    private fun writeConfig(context: Context, name: String, config: String): File {
        val dir = File(context.filesDir, "anytls").apply { mkdirs() }
        return File(dir, name).apply { writeText(config) }
    }
}
