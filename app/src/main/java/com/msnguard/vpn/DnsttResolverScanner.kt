package com.msnguard.vpn

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Ordered DNSTT resolver discovery with persistent, engine-scoped cache. */
internal object DnsttResolverScanner {
    private const val CACHE_NAME = "dnstt-working-resolvers-ir.txt"
    private const val PROGRESS_NAME = "dnstt-resolver-scan-index.txt"
    private const val INPUT_ASSET = "dnstt-resolvers-ir.txt"
    // The input order is part of the selection policy; never parallelize it.
    private const val WORKERS = 1
    private const val PROBE_TIMEOUT_MS = 30_000
    private const val METHOD_TIMEOUT_MS = 12_000L
    // Let the first resolver finish a real tunnel handshake, then let the
    // background scan continue while Tor uses the built-in DoH fallback.
    private const val FIRST_RESULT_TIMEOUT_MS = 15_000L
    private val running = AtomicBoolean(false)
    @Volatile private var scanExecutor: java.util.concurrent.ExecutorService? = null
    @Volatile private var scanProcesses = mutableListOf<Process>()

    fun prepare(context: Context, dataDir: File): String? {
        val cache = File(dataDir, CACHE_NAME)
        val cached = readIps(cache)
        val fresh = context.profiled().getBoolean(TorManager.DNSTT_FRESH_SCAN_PREF, false)
        if (!fresh && cached.isNotEmpty()) {
            ConnectionLog.record("DNSTT cache: using ${cached.size} verified resolver(s)")
            return cached.first()
        }

        if (fresh) {
            cache.delete()
            File(dataDir, PROGRESS_NAME).delete()
            context.profiled().edit().putBoolean(TorManager.DNSTT_FRESH_SCAN_PREF, false).apply()
            ConnectionLog.record("DNSTT Fresh Scan: cache and progress cleared; scanning 7629 resolvers in order")
        }

        val resolvers = readIpsFromAsset(context)
        if (resolvers.isEmpty()) return null
        if (running.get()) {
            ConnectionLog.record("DNSTT resolver scan already running; using current scan")
            return readIps(cache).firstOrNull()
        }
        running.set(true)
        val first = CountDownLatch(1)
        val firstResult = arrayOfNulls<String>(1)
        val progress = File(dataDir, PROGRESS_NAME)
        val next = AtomicInteger(readProgress(progress).coerceIn(0, resolvers.size))
        val executor = Executors.newFixedThreadPool(WORKERS)
        scanExecutor = executor
        repeat(WORKERS) {
            executor.execute {
                while (running.get()) {
                    val index = next.getAndIncrement()
                    if (index >= resolvers.size) break
                    writeProgress(progress, index + 1)
                    val ip = resolvers[index]
                    runCatching {
                        if (probe(context, dataDir, ip)) {
                            appendCache(cache, ip)
                            synchronized(firstResult) {
                                if (firstResult[0] == null) {
                                    firstResult[0] = ip
                                    first.countDown()
                                    ConnectionLog.record("DNSTT resolver #${index + 1}/${resolvers.size} healthy: $ip")
                                }
                            }
                        }
                    }.onFailure { error ->
                        if (running.get()) ConnectionLog.record(
                            "DNSTT resolver #${index + 1} probe error: ${error.message ?: "unknown"}"
                        )
                    }
                }
            }
        }
        Thread({
            executor.shutdown()
            if (executor.awaitTermination(30, TimeUnit.MINUTES)) {
                ConnectionLog.record("DNSTT resolver scan complete: ${readIps(cache).size} healthy resolver(s)")
            }
            running.set(false)
        }, "dnstt-resolver-scan-wait").apply { isDaemon = true }.start()
        first.await(FIRST_RESULT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        val selected = firstResult[0] ?: readIps(cache).firstOrNull()
        if (selected == null) {
            ConnectionLog.record("DNSTT resolver scan still running; starting Tor with DoH fallback")
        }
        return selected
    }

    fun cached(dataDir: File): List<String> = readIps(File(dataDir, CACHE_NAME))

    fun stopScan() {
        running.set(false)
        val processes = synchronized(scanProcesses) {
            val snapshot = scanProcesses.toList()
            scanProcesses.clear()
            snapshot
        }
        processes.forEach { process ->
            runCatching { process.destroy() }
            runCatching { process.destroyForcibly() }
        }
        scanExecutor?.shutdownNow()
        scanExecutor = null
    }

    fun requestFreshScan(context: Context) {
        context.profiled().edit().putBoolean(TorManager.DNSTT_FRESH_SCAN_PREF, true).apply()
        ConnectionLog.record("DNSTT Fresh Scan requested — cache will be cleared on next Tor connect")
    }

    private fun probe(context: Context, dataDir: File, ip: String): Boolean {
        val state = File(dataDir, "dnstt-scan/$ip").apply { mkdirs() }
        val process = runCatching {
            ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libdnstt.so").absolutePath)
                .redirectErrorStream(false)
                .apply {
                    environment()["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
                    environment()["TOR_PT_CLIENT_TRANSPORTS"] = "dnstt"
                    environment()["TOR_PT_STATE_LOCATION"] = state.absolutePath + "/"
                    environment()["TOR_PT_EXIT_ON_STDIN_CLOSE"] = "1"
                    environment()["HOME"] = dataDir.absolutePath
                }.start()
        }.onFailure { error ->
            ConnectionLog.record("DNSTT resolver #$ip process start failed: ${error.message ?: "unknown"}")
        }.getOrNull() ?: return false
        synchronized(scanProcesses) { scanProcesses += process }
        Thread({
            try {
                val reader = process.errorStream.bufferedReader()
                while (true) {
                    val line = try {
                        reader.readLine()
                    } catch (_: java.io.IOException) {
                        break
                    }
                    if (line == null) break
                    if (line.isNotBlank()) {
                        runCatching { ConnectionLog.record("DNSTT scan[$ip]: $line") }
                    }
                }
                runCatching { reader.close() }
            } catch (_: Throwable) {
                // Closing a PT stream during teardown is normal. Never let the
                // scanner log reader reach the process default exception handler.
            }
        }, "dnstt-scan-log-$ip").apply { isDaemon = true }.start()
        return try {
            val listener = readMethod(process)
            if (listener == null) {
                ConnectionLog.record("DNSTT resolver #$ip: no SOCKS listener")
                return false
            }
            val healthy = socksProbe(listener, ip)
            if (!healthy) ConnectionLog.record("DNSTT resolver #$ip: tunnel probe failed")
            healthy
        } finally {
            runCatching { process.outputStream.close() }
            runCatching { process.destroy() }
            synchronized(scanProcesses) { scanProcesses.remove(process) }
        }
    }

    private fun readMethod(process: Process): String? {
        val result = arrayOfNulls<String>(1)
        val done = CountDownLatch(1)
        Thread({
            try {
                process.inputStream.bufferedReader().useLines { lines ->
                    for (raw in lines) {
                        val fields = raw.trim().split(Regex("\\s+"))
                        if (fields.size >= 4 && fields[0] == "CMETHOD" && fields[2] == "socks5") {
                            result[0] = fields[3]
                            break
                        }
                        if (raw.trim() == "CMETHODS DONE") break
                    }
                }
            } catch (_: Throwable) {
                // The process is deliberately terminated after a failed probe.
            } finally {
                done.countDown()
            }
        }, "dnstt-method-reader").apply { isDaemon = true }.start()
        done.await(METHOD_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        return result[0]
    }

    private fun socksProbe(listener: String, resolver: String): Boolean {
        val parts = listener.substringAfterLast(':').toIntOrNull() ?: return false
        return runCatching {
            Socket().use { socket ->
                socket.soTimeout = PROBE_TIMEOUT_MS
                socket.connect(InetSocketAddress("127.0.0.1", parts), PROBE_TIMEOUT_MS)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                output.write(byteArrayOf(5, 1, 2)); output.flush()
                check(input.read() == 5 && input.read() == 2)
                val args = "udp=$resolver:53;pubkey=241169008830694749fe96bb070c4855c5bb5b9c47b3833ed7d88521ba30a43f;domain=t.ruhnama.net"
                // goptlib's PT argument channel is RFC1929 username+password.
                // Use username for the first part and password for the remainder,
                // because Android's SOCKS probe must keep each field <=255 bytes.
                val split = args.indexOf(';').coerceAtLeast(1)
                val username = args.substring(0, split).toByteArray(Charsets.ISO_8859_1)
                val password = args.substring(split).toByteArray(Charsets.ISO_8859_1)
                output.write(byteArrayOf(1, username.size.toByte())); output.write(username)
                output.write(byteArrayOf(password.size.toByte())); output.write(password); output.flush()
                check(input.read() == 1 && input.read() == 0)
                val destination = "1.1.1.1".toByteArray(Charsets.US_ASCII)
                output.write(byteArrayOf(5, 1, 0, 3, destination.size.toByte())); output.write(destination)
                output.write(byteArrayOf(1, 187.toByte())); output.flush()
                input.read() == 5 && input.read() == 0 && input.read() == 0 && input.read() == 3
            }
        }.getOrDefault(false)
    }

    private fun readIpsFromAsset(context: Context): List<String> = runCatching {
        context.assets.open(INPUT_ASSET).bufferedReader().useLines { lines ->
            lines.map(String::trim).filter { it.matches(Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$")) }.toList()
        }
    }.getOrDefault(emptyList())

    private fun readProgress(file: File): Int = runCatching {
        file.readText().trim().toInt()
    }.getOrDefault(0)

    private fun writeProgress(file: File, index: Int) {
        runCatching {
            file.parentFile?.mkdirs()
            file.writeText(index.toString())
        }
    }

    private fun readIps(file: File): List<String> = runCatching {
        if (!file.isFile) emptyList() else file.readLines().map(String::trim).filter(String::isNotEmpty).distinct()
    }.getOrDefault(emptyList())

    private fun appendCache(file: File, ip: String) {
        synchronized(file.absolutePath.intern()) {
            val current = readIps(file)
            if (ip !in current) file.parentFile?.mkdirs().also { file.appendText(if (current.isEmpty()) ip else "\n$ip") }
        }
    }
}
