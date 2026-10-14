package com.msnguard.vpn

import android.content.Context
import android.os.SystemClock
import android.util.Log
import java.io.File

/**
 * Manual WARP identity fetcher for Warp Setting — ECH path only.
 *
 * Runs the bundled engine (libaether.so via [NativeCore]) on
 * 127.0.0.1:1839 so the registration takes the same ECH-camouflaged
 * route a normal WARP connect would. This fixes filtered carriers
 * where a plain HttpURLConnection POST to api.cloudflareclient.com
 * times out, while the engine's BoringSSL + ECH stack reaches it.
 *
 * Implementation is NativeCore-based, not ProcessBuilder: libaether.so
 * is a cdylib (JNI), not a standalone executable, so exec fails.
 * The engine is started as a job (AETHER_* env), polled for the
 * identity files (aether.toml etc), then stopped. Mirrors the main
 * WARP connect's ECH path (AETHER_API_ECH embedded, no DoH).
 *
 * Scope is strictly Warp Setting: it never starts the main tunnel,
 * never touches SHARD/Tor/Psiphon/WireGuard/WoW/Masque connect flow,
 * and only writes the identity files the core later loads.
 */
object WarpIdentityFetcher {

    private const val TAG = "WarpIdentity"
    private const val BIND = "127.0.0.1:1839"
    private const val TIMEOUT_MS = 240_000L
    private const val POLL_MS = 400L
    private const val BACKUP_SUFFIX = ".warp-bak"

    private const val PRIMARY_WG = "aether.toml"
    private const val SECONDARY_WG = "aether-secondary.toml"
    private const val PRIMARY_MASQUE = "aether-masque.toml"
    private const val SECONDARY_MASQUE = "aether-masque-secondary.toml"
    private val ALL_FILES = listOf(PRIMARY_WG, SECONDARY_WG, PRIMARY_MASQUE, SECONDARY_MASQUE)

    fun canRun(): Boolean = !NativeCore.isRunning()

    fun fetch(context: Context, protocol: String): Boolean {
        if (NativeCore.isRunning()) {
            Log.w(TAG, "tunnel is running — disconnect before fetching identity")
            ConnectionLog.record("Warp Identity: tunnel is running — disconnect first")
            return false
        }

        val dir = context.filesDir
        val norm = protocol.lowercase()
        val masque = norm in setOf("masque", "mim", "masque-in-masque", "masque over masque")
        val targets = identityFiles(dir, norm)
        if (targets.isEmpty()) {
            Log.w(TAG, "unknown protocol $protocol")
            return false
        }

        recover(dir)

        val moved = mutableListOf<File>()
        for (file in targets) {
            if (!file.exists()) continue
            val bak = backupOf(file)
            bak.delete()
            if (!file.renameTo(bak)) {
                Log.e(TAG, "could not set ${file.name} aside")
                ConnectionLog.record("Warp Identity: could not set ${file.name} aside")
                restore(moved)
                return false
            }
            moved += file
        }

        var ok = false
        try {
            val env = buildEnv(context, norm)
            Log.i(TAG, "requesting fresh $protocol identity via ECH (bind $BIND)")
            ConnectionLog.record("Warp Identity: requesting $protocol via ECH")

            CoreConfig.applyEnv(env)
            val startRc = try {
                NativeCore.startProxy("{}")
            } catch (e: Exception) {
                Log.w(TAG, "NativeCore start failed: ${e.message}")
                -1
            }
            if (startRc != 0 && !NativeCore.isRunning()) {
                val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                Log.w(TAG, "engine did not start: $err")
                ConnectionLog.record("Warp Identity: engine did not start${if (err.isNotBlank()) " — $err" else ""}")
                restore(moved)
                return false
            }

            val deadline = SystemClock.elapsedRealtime() + TIMEOUT_MS
            while (true) {
                if (targets.all { complete(it, masque) }) {
                    ok = true
                    break
                }
                if (!NativeCore.isRunning()) {
                    // Job finished (success or failure) — check files one last time.
                    ok = targets.all { complete(it, masque) }
                    if (!ok) {
                        val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                        if (err.isNotBlank()) {
                            Log.w(TAG, "engine finished without identity: $err")
                            ConnectionLog.record("Warp Identity: $protocol — $err")
                        }
                    }
                    break
                }
                if (SystemClock.elapsedRealtime() >= deadline) {
                    Log.w(TAG, "Warp identity request timed out after ${TIMEOUT_MS}ms")
                    ConnectionLog.record("Warp Identity: timed out after ${TIMEOUT_MS / 1000}s")
                    break
                }
                try { Thread.sleep(POLL_MS) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Warp identity fetcher crashed: ${e.message}")
            ConnectionLog.record("Warp Identity: crashed — ${e.message}")
        } finally {
            try { NativeCore.stop() } catch (_: Exception) {}
            // Small grace for file flush
            try { Thread.sleep(300) } catch (_: InterruptedException) {}
            if (ok) {
                moved.forEach { backupOf(it).delete() }
                // Also clean any stale bak that recover would have handled
                Log.i(TAG, "new $protocol identity saved via ECH")
                ConnectionLog.record("Warp Identity: $protocol saved")
            } else {
                restore(moved)
                Log.w(TAG, "$protocol Warp identity failed — previous identity kept")
                ConnectionLog.record("Warp Identity: $protocol failed — previous kept")
            }
        }
        return ok
    }

    private fun buildEnv(context: Context, norm: String): Map<String, String> {
        val protoForEnv = when (norm) {
            "masque", "mim", "masque-in-masque", "masque over masque" -> "masque"
            "gool", "wow", "warp-in-warp" -> "gool"
            else -> "wireguard"
        }
        val base = CoreConfig.env(context, protocol = protoForEnv)
        val out = LinkedHashMap(base)
        // Quantum ECH: force Freedom-like ECH regardless of current exit mode.
        // Use embedded AETHER_API_ECH (no DoH to 1.1.1.1) — same key main
        // connect embeds for Freedom direct, so filtered carriers need no
        // extra round-trip. Remove AETHER_ECH/AETHER_UPSTREAM like Freedom.
        out["AETHER_API_ECH"] = "AEX+DQBBrwAgACCbK1mYDYFz/BAn6S5t+Q/v+Oej3eFNxtPWgz50fNnFPAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
        out.remove("AETHER_ECH")
        out.remove("AETHER_ECH_DNS")
        out.remove("AETHER_ECH_DOMAIN")
        out.remove("AETHER_UPSTREAM")
        out["AETHER_SOCKS"] = BIND
        out["AETHER_SCAN"] = "turbo"
        out["AETHER_QUICK_RECONNECT"] = "0"
        out["AETHER_LOG_LEVEL"] = "info"
        // Consumer WARP only
        out.remove("AETHER_TEAM")
        out.remove("AETHER_ACCESS_CLIENT_ID")
        out.remove("AETHER_ACCESS_CLIENT_SECRET")
        out.remove("AETHER_ACCESS_TOKEN")
        out.remove("AETHER_ACCESS_EMAIL")
        out.remove("AETHER_GATEWAY")
        return out
    }

    private fun identityFiles(dir: File, norm: String): List<File> = when (norm) {
        "wireguard", "wg" -> listOf(PRIMARY_WG)
        "gool", "wow", "warp-in-warp" -> listOf(PRIMARY_WG, SECONDARY_WG)
        "masque" -> listOf(PRIMARY_MASQUE)
        "mim", "masque-in-masque", "masque over masque" -> listOf(PRIMARY_MASQUE, SECONDARY_MASQUE)
        else -> emptyList()
    }.map { File(dir, it) }

    private fun backupOf(file: File): File = File(file.parentFile, file.name + BACKUP_SUFFIX)

    private fun restore(moved: List<File>) {
        for (file in moved) {
            val bak = backupOf(file)
            if (!bak.exists()) continue
            file.delete()
            if (!bak.renameTo(file)) Log.w(TAG, "could not restore ${file.name}")
        }
    }

    private fun recover(dir: File) {
        for (name in ALL_FILES) {
            val file = File(dir, name)
            val bak = backupOf(file)
            if (!bak.exists()) continue
            if (complete(file, name.contains("masque"))) bak.delete()
            else { file.delete(); bak.renameTo(file) }
        }
    }

    private fun complete(file: File, masque: Boolean): Boolean {
        val text = runCatching { file.readText() }.getOrNull() ?: return false
        if (!hasValue(text, "device_id")) return false
        if (!hasValue(text, "wg_private_key") || !hasValue(text, "wg_peer_public_key")) return false
        return !masque || (hasValue(text, "cert_pem") && hasValue(text, "key_pem"))
    }

    private fun hasValue(text: String, key: String): Boolean {
        val m = Regex("""(?m)^\s*${Regex.escape(key)}\s*=\s*(.+)$""").find(text) ?: return false
        val v = m.groupValues[1].trim()
        return v.isNotEmpty() && v != "\"\"" && v != "''"
    }
}
