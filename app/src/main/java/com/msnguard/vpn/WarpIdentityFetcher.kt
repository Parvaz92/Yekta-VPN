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

    // Quantum ECH embedded key — same value CoreConfig embeds for the
    // Freedom/direct API path. One constant here so fetcher env was never
    // derived from the tunnel's map. (CHANGED in isolation: see buildEnv doc.)
    // buildEnv prefers a DNS-verified fresher blob from EchEndpointRoster
    // (see its doc) — this constant is the always-works fallback.
    private const val ECH_EMBEDDED =
        "AEX+DQBBrwAgACCbK1mYDYFz/BAn6S5t+Q/v+Oej3eFNxtPWgz50fNnFPAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

    fun canRun(): Boolean = !NativeCore.isRunning()

    // Tunnel-carry-over env keys a previous connect may have left set. The
    // register job must run on a MINIMAL env: any leftover engine knob from
    // the last tunnel polluted AETHER_REGISTER and made it exit without a
    // file after any connect. Warp Setting isolated — the connect path sets
    // these again via CoreConfig.applyEnv on the next start.
    private val TUNNEL_ENV_KEYS = listOf(
        "AETHER_REGISTER",            // stale set would re-register wrongly
        "AETHER_QUICK_RECONNECT", "AETHER_STATS", "AETHER_STATS_SECS",
        "AETHER_SCAN", "AETHER_IP", "AETHER_NOIZE", "AETHER_PERF_PROFILE",
        "AETHER_SCAN_CIDRS_V4", "AETHER_SCAN_CIDRS_V6", "AETHER_WG_PORTS", "AETHER_PTECH_SCAN",
        "AETHER_PEER", "AETHER_WG_PEER", "AETHER_WIW_INNER_PEER", "AETHER_MIM_INNER_PEER",
        "AETHER_MASQUE_HTTP2", "AETHER_MASQUE_SNI", "AETHER_MASQUE_H2_FRAGMENT", "AETHER_MASQUE_H2_FRAGMENT_SNI",
        "AETHER_MASQUE_MTU", "AETHER_WG_MTU", "AETHER_HTTP_PROXY", "AETHER_GOOL_MODE",
        "AETHER_TLS_GROUPS", "AETHER_TLS_CIPHERS", "AETHER_DNS", "AETHER_ROUTE_BLOCK", "AETHER_ROUTE_DIRECT",
        "AETHER_TEAM", "AETHER_ACCESS_CLIENT_ID", "AETHER_ACCESS_CLIENT_SECRET",
        "AETHER_ACCESS_TOKEN", "AETHER_ACCESS_EMAIL", "AETHER_ACCESS_GATEWAY",
        "AETHER_ECH", "AETHER_ECH_DNS", "AETHER_ECH_DOMAIN", "AETHER_API_ECH",
        "AETHER_UPSTREAM",
    )

    /**
     * Why [file] is not a complete identity, or null when it is. Stage-F log
     * data: names the exact missing field, so a follow-up log shows WHERE the
     * registration died instead of a bare "failed — previous kept".
     */
    private fun whyIncomplete(file: File, masque: Boolean): String? {
        val text = runCatching { file.readText() }.getOrNull() ?: return "file-not-found"
        val missing = mutableListOf<String>()
        if (!hasValue(text, "device_id")) missing.add("device_id")
        if (!hasValue(text, "wg_private_key")) missing.add("wg_private_key")
        if (!hasValue(text, "wg_peer_public_key")) missing.add("wg_peer_public_key")
        if (masque) {
            if (!hasValue(text, "cert_pem")) missing.add("cert_pem")
            if (!hasValue(text, "key_pem")) missing.add("key_pem")
        }
        return if (missing.isEmpty()) null else "missing=" + missing.joinToString(",")
    }

    /** One-line state for the stage log: exists? size? what is missing? */
    private fun targetState(file: File, masque: Boolean): String {
        if (!file.exists()) return file.name + "=absent"
        val why = whyIncomplete(file, masque)
        return file.name + "=" + file.length() + "B" + (if (why != null) " ($why)" else " ok")
    }

    /** Stage-C: install the minimal env and clear every tunnel carry-over. */
    private fun sanitizeAndApplyEnv(context: Context, out: Map<String, String>): Int {
        var cleared = 0
        for (key in TUNNEL_ENV_KEYS) {
            if (key !in out) { NativeCore.clearEnv(key); cleared++ }
        }
        for ((key, value) in out) NativeCore.setEnv(key, value)
        val ech = if (out.containsKey("AETHER_API_ECH")) "ech=on" else "ech=off"
        val up = out["AETHER_UPSTREAM"]?.let { "upstream=shard" } ?: "upstream=none"
        ConnectionLog.record(
            "Warp Identity: stage ok — env set (" + out.size + " keys, " + cleared + " tunnel carry-overs cleared; " +
                "proto=" + out["AETHER_PROTOCOL"] + " register=" + out["AETHER_REGISTER"] + " " + ech + " " + up + ")"
        )
        return cleared
    }

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
        // Arm the ECH fallback roster (async, cache-first — see its doc).
        EchEndpointRoster.maybeProbe(context)

        // Stage A — file quiesce: recover stale baks, move aside targets, log exactly what was moved.
        ConnectionLog.record("Warp Identity: stage A — file quiesce for $protocol")
        recover(dir)

        val moved = mutableListOf<File>()
        for (file in targets) {
            if (!file.exists()) continue
            val bak = backupOf(file)
            bak.delete()
            if (!file.renameTo(bak)) {
                Log.e(TAG, "could not set ${file.name} aside")
                ConnectionLog.record("Warp Identity: stage A failed — could not set ${file.name} aside")
                restore(moved)
                return false
            }
            moved += file
            ConnectionLog.record("Warp Identity: stage A — moved aside " + file.name + " (" + targets.map { targetState(it, masque) }.joinToString(" | ") + ")")
        }
        if (moved.isEmpty()) {
            ConnectionLog.record("Warp Identity: stage A — no prior " + protocol + " file to move (fresh registration)")
        }

        var ok = false
        try {
            val env = buildEnv(context, norm)
            Log.i(TAG, "requesting fresh $protocol identity via ECH (bind $BIND)")
            ConnectionLog.record("Warp Identity: requesting $protocol via ECH…")
            ConnectionLog.record("Warp Identity: registering $protocol…")
            // Stage C — env sanitize: clear previous tunnel's env carry-over, set minimal register env.
            ConnectionLog.record("Warp Identity: stage C — sanitizing env (clearing tunnel carry-overs)")
            sanitizeAndApplyEnv(context, env)

            // Stage D — engine start
            ConnectionLog.record("Warp Identity: stage D — starting engine (proxy on $BIND, proto=" + protocol + ")")
            var startRc = try {
                NativeCore.startProxy("{}")
            } catch (e: Exception) {
                Log.w(TAG, "NativeCore start failed: ${e.message}")
                -1
            }
            if (startRc != 0 && !NativeCore.isRunning()) {
                val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                val hint = if (err.isNotBlank()) " — $err" else " (no engine error text — JNI g_last_error cached)"
                Log.w(TAG, "engine did not start: $err (rc=$startRc isRunning=" + NativeCore.isRunning() + ")")
                ConnectionLog.record("Warp Identity: stage D failed — engine did not start$hint")
                // Stage F detail: which file was expected and what is there
                ConnectionLog.record("Warp Identity: stage F — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                restore(moved)
                return false
            }
            ConnectionLog.record("Warp Identity: stage D ok — engine started (rc=$startRc isRunning=" + NativeCore.isRunning() + ")")

            val deadline = SystemClock.elapsedRealtime() + TIMEOUT_MS
            // Stage E — wait for the identity file; every few seconds a WHY line so a
            // follow-up log shows exactly which field is missing and how much arrived.
            var lastStageLog = 0L
            while (true) {
                if (targets.all { complete(it, masque) }) {
                    ok = true
                    break
                }
                val finished = !NativeCore.isRunning()
                if (finished || SystemClock.elapsedRealtime() >= deadline) {
                    if (!finished && SystemClock.elapsedRealtime() >= deadline) {
                        Log.w(TAG, "Warp identity request timed out after ${TIMEOUT_MS}ms")
                        ConnectionLog.record("Warp Identity: stage E — timed out after " + (TIMEOUT_MS / 1000) + "s")
                    }
                    // Stage F — final verdict with exact per-file state
                    ok = targets.all { complete(it, masque) }
                    if (!ok) {
                        val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                        val engineNote = if (err.isNotBlank()) "engine-error=[$err]" else "engine-error=none (job done ok or reaped silently)"
                        ConnectionLog.record(
                            "Warp Identity: stage F — " + (if (finished) "engine exited without identity" else "timed out") +
                                "; " + targets.joinToString(" | ") { t -> targetState(t, masque) } + "; " + engineNote
                        )
                    } else {
                        ConnectionLog.record("Warp Identity: stage G ok — " + targets.joinToString(" | ") { t -> t.name + "=complete" })
                    }
                    break
                }
                // Live tick so vault term visibly moves while engine works + a WHY snapshot
                val now = SystemClock.elapsedRealtime()
                if (now % 4000 < 500 && lastStageLog != 0L && now - lastStageLog >= 3800) {
                    ConnectionLog.record("Warp Identity: still working on $protocol… — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                    lastStageLog = now
                }
                // Live tick so vault term visibly moves while engine works
                else if (now % 4000 < 500) {
                    ConnectionLog.record("Warp Identity: still working on $protocol…")
                    lastStageLog = now
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

    /**
     * Warp Setting — bare identity (no ECH, no Shard), for users outside Iran where
     * api.cloudflareclient.com is openly reachable but 1.1.1.1 DoH is not.
     * Uses the engine with a plain route (no ECH material, no upstream).
     * Isolated to Warp Setting only.
     */
    fun fetchDirectPlain(context: Context, protocol: String): Boolean {
        if (NativeCore.isRunning()) {
            android.util.Log.w(TAG, "tunnel is running — disconnect before fetching identity")
            ConnectionLog.record("Warp Identity: tunnel is running — disconnect first")
            return false
        }
        val dir = context.filesDir
        val norm = protocol.lowercase()
        val masque = norm in setOf("masque", "mim", "masque-in-masque", "masque over masque")
        val targets = identityFiles(dir, norm)
        if (targets.isEmpty()) return false
        ConnectionLog.record("Warp Identity: stage A — file quiesce for $protocol (plain)")
        recover(dir)
        val moved = mutableListOf<java.io.File>()
        for (file in targets) {
            if (!file.exists()) continue
            val bak = backupOf(file); bak.delete()
            if (!file.renameTo(bak)) {
                android.util.Log.e(TAG, "could not set " + file.name + " aside")
                ConnectionLog.record("Warp Identity: stage A failed — could not set " + file.name + " aside")
                restore(moved); return false
            }
            moved += file
        }
        if (moved.isEmpty()) ConnectionLog.record("Warp Identity: stage A — no prior " + protocol + " file to move (fresh registration)")
        var ok = false
        try {
            val env = buildEnvPlain(context, norm)
            android.util.Log.i(TAG, "requesting fresh " + protocol + " identity via Native Link (bind " + BIND + ")")
            ConnectionLog.record("Warp Identity: requesting " + protocol + " via Native Link…")
            ConnectionLog.record("Warp Identity: registering " + protocol + "…")
            ConnectionLog.record("Warp Identity: stage C — sanitizing env (clearing tunnel carry-overs)")
            sanitizeAndApplyEnv(context, env)
            ConnectionLog.record("Warp Identity: stage D — starting engine (proxy on " + BIND + ", proto=" + protocol + ")")
            val startRc = try { NativeCore.startProxy("{}") } catch (e: Exception) { android.util.Log.w(TAG, "NativeCore start failed: " + e.message); -1 }
            if (startRc != 0 && !NativeCore.isRunning()) {
                val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                android.util.Log.w(TAG, "engine did not start: " + err)
                ConnectionLog.record("Warp Identity: stage D failed — engine did not start" + (if (err.isNotBlank()) " — " + err else ""))
                ConnectionLog.record("Warp Identity: stage F — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                restore(moved); return false
            }
            ConnectionLog.record("Warp Identity: stage D ok — engine started (rc=$startRc isRunning=" + NativeCore.isRunning() + ")")
            val deadline = android.os.SystemClock.elapsedRealtime() + TIMEOUT_MS
            var lastStageLog = 0L
            while (true) {
                if (targets.all { complete(it, masque) }) { ok = true; break }
                val finished = !NativeCore.isRunning()
                if (finished || android.os.SystemClock.elapsedRealtime() >= deadline) {
                    if (!finished) {
                        android.util.Log.w(TAG, "Warp identity request timed out after " + TIMEOUT_MS + "ms")
                        ConnectionLog.record("Warp Identity: stage E — timed out after " + (TIMEOUT_MS / 1000) + "s")
                    }
                    ok = targets.all { complete(it, masque) }
                    if (!ok) {
                        val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                        val engineNote = if (err.isNotBlank()) "engine-error=[$err]" else "engine-error=none"
                        ConnectionLog.record(
                            "Warp Identity: stage F — " + (if (finished) "engine exited without identity" else "timed out") +
                                "; " + targets.joinToString(" | ") { t -> targetState(t, masque) } + "; " + engineNote
                        )
                    } else ConnectionLog.record("Warp Identity: stage G ok — " + targets.joinToString(" | ") { t -> t.name + "=complete" })
                    break
                }
                val now = android.os.SystemClock.elapsedRealtime()
                if (now % 4000 < 500) {
                    ConnectionLog.record("Warp Identity: still working on $protocol… — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                    lastStageLog = now
                }
                try { Thread.sleep(POLL_MS) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        } catch (e: Exception) { android.util.Log.w(TAG, "Warp identity fetcher crashed: " + e.message); ConnectionLog.record("Warp Identity: crashed — " + e.message) }
        finally {
            try { NativeCore.stop() } catch (_: Exception) {}
            try { Thread.sleep(300) } catch (_: InterruptedException) {}
            if (ok) { moved.forEach { backupOf(it).delete() }; android.util.Log.i(TAG, "new " + protocol + " identity saved via Native Link"); ConnectionLog.record("Warp Identity: " + protocol + " saved") }
            else { restore(moved); android.util.Log.w(TAG, protocol + " Warp identity failed — previous identity kept"); ConnectionLog.record("Warp Identity: " + protocol + " failed — previous kept") }
        }
        return ok
    }

    private fun buildEnvPlain(context: Context, norm: String): Map<String, String> {
        val protoForEnv = when (norm) { "mim", "masque-in-masque", "masque over masque" -> "mim"; "masque" -> "masque"; "gool", "wow", "warp-in-warp" -> "gool"; else -> "wireguard" }
        // Same minimal construction as buildEnv — registration needs no scan
        // env from a previous tunnel; a stale AETHER_NOIZE/SCAN/MTU/SNI/TLS
        // set made the register job exit without a file after any connect.
        val out = LinkedHashMap<String, String>()
        out["AETHER_CONFIG"] = File(context.filesDir, "aether.toml").absolutePath
        out["AETHER_PROTOCOL"] = protoForEnv
        out["AETHER_SOCKS"] = BIND
        out["AETHER_LOG_LEVEL"] = "info"
        // Plain route: no ECH at all, no upstream — raw carrier to api.cloudflareclient.com
        out["AETHER_REGISTER"] = when (protoForEnv) { "mim" -> "mim"; "masque" -> "masque"; "gool" -> "gool"; else -> "wg" }
        // Consumer WARP only — no Zero Trust carry-over from a previous connect.
        return out
    }

    /**
     * Warp Setting — Shard path (2.1.0 mechanism, isolated) with cache-first.
     * Tries the health-ranked top slice quickly; if none answers, falls back to full sweep (ensureShardListener).
     * Bring SHARD up, set AETHER_UPSTREAM=socks5://127.0.0.1:port, run the engine so it registers
     * through the listener (same as main connect), wait for identity files, then tear down SHARD.
     * Scope is Warp Setting only — core logic itself is untouched.
     */
    fun fetchViaShard(context: Context, protocol: String): Boolean {
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
        // Warp Setting cache-first: try health-ranked top slice quickly; if none answers, full sweep.
        val wasRunning = ShardManager.isRunning
        if (!wasRunning) {
            ConnectionLog.record("Warp Identity: trying cached SHARD nodes first…")
            val fastStarted = tryFastShard(context)
            if (fastStarted != null) {
                ConnectionLog.record("Warp Identity: cached SHARD ready — registering " + protocol + "…")
                return finishShardProvision(context, norm, protocol, masque, dir, targets, moved, fastStarted, wasRunning)
            }
            ConnectionLog.record("Warp Identity: cached SHARD did not answer — full scan…")
        }
        ConnectionLog.record("Warp Identity: bringing SHARD up…")
        var listener: String? = IdentityProvisioner.ensureShardListener(context)
        if (listener == null) {
            ConnectionLog.record("Warp Identity: SHARD busy — retrying…")
            try { Thread.sleep(1200) } catch (_: InterruptedException) {}
            listener = IdentityProvisioner.ensureShardListener(context)
        }
        if (listener == null) {
            Log.w(TAG, "SHARD listener not available for $protocol")
            ConnectionLog.record("Warp Identity: SHARD listener not available for $protocol")
            restore(moved)
            return false
        }
        val upstream = when {
            listener.startsWith("socks5://", ignoreCase = true) -> listener
            listener.contains("://") -> listener
            else -> "socks5://$listener"
        }
        var ok = false
        try {
            val env = buildEnvForShard(context, norm, upstream)
            Log.i(TAG, "requesting fresh $protocol identity via SHARD ($upstream)")
            ConnectionLog.record("Warp Identity: requesting $protocol via Shard…")
            ConnectionLog.record("Warp Identity: SHARD ready — registering $protocol…")
            ConnectionLog.record("Warp Identity: stage C — sanitizing env (clearing tunnel carry-overs)")
            sanitizeAndApplyEnv(context, env)
            ConnectionLog.record("Warp Identity: stage D — starting engine (proxy on $BIND, proto=" + protocol + ", upstream=shard)")
            val startRc = try { NativeCore.startProxy("{}") } catch (e: Exception) { Log.w(TAG, "NativeCore start failed: ${e.message}"); -1 }
            if (startRc != 0 && !NativeCore.isRunning()) {
                val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                Log.w(TAG, "engine did not start: $err")
                ConnectionLog.record("Warp Identity: stage D failed — engine did not start" + (if (err.isNotBlank()) " — " + err else ""))
                ConnectionLog.record("Warp Identity: stage F — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                restore(moved)
                return false
            }
            ConnectionLog.record("Warp Identity: stage D ok — engine started (rc=$startRc isRunning=" + NativeCore.isRunning() + ")")
            val deadline = SystemClock.elapsedRealtime() + TIMEOUT_MS
            while (true) {
                if (targets.all { complete(it, masque) }) { ok = true; break }
                val finished = !NativeCore.isRunning()
                if (finished || SystemClock.elapsedRealtime() >= deadline) {
                    if (!finished) {
                        Log.w(TAG, "Warp identity request timed out after ${TIMEOUT_MS}ms")
                        ConnectionLog.record("Warp Identity: stage E — timed out after ${TIMEOUT_MS / 1000}s")
                    }
                    ok = targets.all { complete(it, masque) }
                    if (!ok) {
                        val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                        val engineNote = if (err.isNotBlank()) "engine-error=[$err]" else "engine-error=none"
                        ConnectionLog.record(
                            "Warp Identity: stage F — " + (if (finished) "engine exited without identity" else "timed out") +
                                "; " + targets.joinToString(" | ") { t -> targetState(t, masque) } + "; " + engineNote
                        )
                    } else ConnectionLog.record("Warp Identity: stage G ok — " + targets.joinToString(" | ") { t -> t.name + "=complete" })
                    break
                }
                val now = SystemClock.elapsedRealtime()
                if (now % 4000 < 500) {
                    ConnectionLog.record("Warp Identity: still working on $protocol… — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                }
                try { Thread.sleep(POLL_MS) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Warp identity fetcher crashed: ${e.message}")
            ConnectionLog.record("Warp Identity: crashed — ${e.message}")
        } finally {
            try { NativeCore.stop() } catch (_: Exception) {}
            try { Thread.sleep(300) } catch (_: InterruptedException) {}
            // Only tear down SHARD when we started it — same rule as provisionViaShard.
            if (!wasRunning) try { IdentityProvisioner.releaseShardListener(startedOurselves = true) } catch (_: Exception) {}
            if (ok) {
                moved.forEach { backupOf(it).delete() }
                Log.i(TAG, "new $protocol identity saved via SHARD")
                ConnectionLog.record("Warp Identity: $protocol saved via Shard")
            } else {
                restore(moved)
                Log.w(TAG, "$protocol Warp identity via Shard failed — previous kept")
                ConnectionLog.record("Warp Identity: $protocol via Shard failed — previous kept")
            }
        }
        return ok
    }

    /** Cache-first: race only the health-ranked top slice (<=24 nodes, ~12s). Returns upstream if winner found. */
    private fun tryFastShard(context: Context): String? {
        val pool = ShardSubscription.nodes(context)
        if (pool.isEmpty()) return null
        val ranked = ShardHealth.rank(context, pool)
        if (ranked.isEmpty()) return null
        val slice = ranked.take(24)
        if (slice.isEmpty()) return null
        // Run a single-slice race inline (probe only) then lift the winner to a live tunnel.
        // We reuse ShardConfigs.probeConfig + manual live launch on SOCKS_PORT, but keep it Warp Setting local:
        // start a one-slice probe on a temp port block, pick winner, then start live tunnel on SOCKS_PORT.
        val probeBase = 21160
        val anytlsBase = 21260
        val xray = slice.filter { it.protocol != "anytls" }
        val anytls = slice.filter { it.protocol == "anytls" }
        var probeProc: Process? = null
        var anytlsLaunched = false
        try {
            if (xray.isNotEmpty()) {
                val cfg = ShardConfigs.probeConfig(context, xray, probeBase)
                val f = ShardConfigs.writeConfig(context, "warp-fast-probe.json", cfg)
                val bin = java.io.File(context.applicationInfo.nativeLibraryDir, "libxray.so")
                if (!bin.exists()) return null
                try {
                    val pb = ProcessBuilder(bin.absolutePath, "run", "-c", f.absolutePath)
                    pb.directory(f.parentFile); pb.redirectErrorStream(true)
                    pb.environment()["HOME"] = context.filesDir.absolutePath
                    pb.environment()["XRAY_LOCATION_ASSET"] = f.parent
                    probeProc = pb.start()
                    Thread({ try { java.io.BufferedReader(java.io.InputStreamReader(probeProc.inputStream)).forEachLine{} } catch(_: Exception){} }, "warp-fast-probe-log").apply{ isDaemon = true }.start()
                } catch(_: Exception){ return null }
            }
            if (anytls.isNotEmpty()) {
                val map = anytls.mapIndexed { i, n -> n to (anytlsBase + i) }.toMap()
                anytlsLaunched = try { AnyTlsManager.launchProbe(context, anytls, map) } catch(_: Exception){ false }
                if (!anytlsLaunched && probeProc == null) return null
            }
            val upProbe = if (probeProc != null) awaitPort(probeBase, 4000) else true
            if (!upProbe) return null
            if (anytlsLaunched && !awaitPort(anytlsBase, 4000)) return null
            ConnectionLog.record("Warp Identity: fast racing " + slice.size + " nd — budget 12000ms, per-nd 5000ms")
            val portOf = HashMap<ShardNode, Int>()
            slice.forEachIndexed { idx, node -> portOf[node] = if (node.protocol == "anytls") anytlsBase + anytls.indexOf(node) else probeBase + xray.indexOf(node) }
            val winnerRef = java.util.concurrent.atomic.AtomicReference<ShardNode?>(null)
            val latch = java.util.concurrent.CountDownLatch(1)
            val pool2 = java.util.concurrent.Executors.newFixedThreadPool(slice.size.coerceAtMost(24))
            slice.forEach { node ->
                pool2.execute {
                    if (winnerRef.get() != null) return@execute
                    val s = System.currentTimeMillis()
                    val (ok, _) = ShardProbe.checkDetailed(portOf.getValue(node), 5000)
                    val elapsed = (System.currentTimeMillis() - s).toInt()
                    if (ok) { ShardHealth.recordSuccess(context, node, elapsed); if (winnerRef.compareAndSet(null, node)) latch.countDown() }
                    else ShardHealth.recordFailure(context, node)
                }
            }
            latch.await(12000, java.util.concurrent.TimeUnit.MILLISECONDS)
            pool2.shutdownNow()
            val winner = winnerRef.get() ?: return null
            ConnectionLog.record("Warp Identity: fast winner " + LogRedactor.nodeTag(winner.key))
            // Bring winner up as live tunnel on SOCKS_PORT
            if (winner.protocol == "anytls") {
                if (!AnyTlsManager.launchLive(context, winner, "127.0.0.1", ShardManager.SOCKS_PORT, false)) return null
            } else {
                val cfg = ShardConfigs.tunnelConfig(context, winner, "127.0.0.1", ShardManager.SOCKS_PORT, "warning")
                val f = ShardConfigs.writeConfig(context, "tunnel.json", cfg)
                val bin = java.io.File(context.applicationInfo.nativeLibraryDir, "libxray.so")
                if (!bin.exists()) return null
                try {
                    val pb = ProcessBuilder(bin.absolutePath, "run", "-c", f.absolutePath)
                    pb.directory(f.parentFile); pb.redirectErrorStream(true)
                    pb.environment()["HOME"] = context.filesDir.absolutePath
                    pb.environment()["XRAY_LOCATION_ASSET"] = f.parent
                    val proc = pb.start()
                    Thread({ try{ java.io.BufferedReader(java.io.InputStreamReader(proc.inputStream)).forEachLine{} }catch(_: Exception){} }, "warp-fast-live-log").apply{ isDaemon=true }.start()
                    val dl = System.currentTimeMillis()+6000
                    var up = false
                    while (System.currentTimeMillis()<dl) {
                        if (portAccepts(ShardManager.SOCKS_PORT, 400)) { up = true; break }
                        if (!proc.isAlive) break
                        Thread.sleep(120)
                    }
                    if (!up) { try{ proc.destroy() }catch(_:Exception){}; return null }
                    // Keep proc alive: patch ShardManager internal state so stop()/isRunning behave
                    // Use reflection to set private process/activeNode/running/liveEngine — isolated, Warp Setting only.
                    try {
                        val m = ShardManager::class.java
                        m.getDeclaredField("process").apply{ isAccessible = true }.set(ShardManager, proc)
                        m.getDeclaredField("running").apply{ isAccessible = true }.let{ fld ->
                            val ab = fld.get(ShardManager) as java.util.concurrent.atomic.AtomicBoolean
                            ab.set(true)
                        }
                        m.getDeclaredField("activeNode").apply{ isAccessible = true }.set(ShardManager, winner)
                        // liveEngine defaults to XRAY (null treated as xray)
                    } catch(_: Exception) {}
                } catch(_: Exception){ return null }
            }
            return "127.0.0.1:" + ShardManager.SOCKS_PORT
        } finally {
            try { probeProc?.destroy() } catch(_: Exception){}
            if (anytlsLaunched) try { AnyTlsManager.killProbe() } catch(_: Exception){}
        }
    }

    private fun finishShardProvision(context: Context, norm: String, protocol: String, masque: Boolean, dir: java.io.File, targets: List<java.io.File>, moved: MutableList<java.io.File>, upstreamRaw: String, wasRunning: Boolean): Boolean {
        val upstream = when { upstreamRaw.startsWith("socks5://", ignoreCase = true) -> upstreamRaw; upstreamRaw.contains("://") -> upstreamRaw; else -> "socks5://" + upstreamRaw }
        var ok = false
        try {
            val env = buildEnvForShard(context, norm, upstream)
            android.util.Log.i(TAG, "requesting fresh " + protocol + " identity via SHARD (" + upstream + ")")
            ConnectionLog.record("Warp Identity: SHARD ready — registering " + protocol + "…")
            ConnectionLog.record("Warp Identity: stage C — sanitizing env (clearing tunnel carry-overs)")
            sanitizeAndApplyEnv(context, env)
            ConnectionLog.record("Warp Identity: stage D — starting engine (proxy on " + BIND + ", proto=" + protocol + ", upstream=shard)")
            val startRc = try { NativeCore.startProxy("{}") } catch (e: Exception) { android.util.Log.w(TAG, "NativeCore start failed: " + e.message); -1 }
            if (startRc != 0 && !NativeCore.isRunning()) {
                val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                android.util.Log.w(TAG, "engine did not start: " + err)
                ConnectionLog.record("Warp Identity: stage D failed — engine did not start" + (if (err.isNotBlank()) " — " + err else ""))
                ConnectionLog.record("Warp Identity: stage F — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                restore(moved); return false
            }
            ConnectionLog.record("Warp Identity: stage D ok — engine started (rc=$startRc isRunning=" + NativeCore.isRunning() + ")")
            val deadline = android.os.SystemClock.elapsedRealtime() + TIMEOUT_MS
            while (true) {
                if (targets.all { complete(it, masque) }) { ok = true; break }
                val finished = !NativeCore.isRunning()
                if (finished || android.os.SystemClock.elapsedRealtime() >= deadline) {
                    if (!finished) {
                        android.util.Log.w(TAG, "Warp identity request timed out after " + TIMEOUT_MS + "ms")
                        ConnectionLog.record("Warp Identity: stage E — timed out after " + TIMEOUT_MS / 1000 + "s")
                    }
                    ok = targets.all { complete(it, masque) }
                    if (!ok) {
                        val err = try { NativeCore.lastError() } catch (_: Exception) { "" }
                        val engineNote = if (err.isNotBlank()) "engine-error=[$err]" else "engine-error=none"
                        ConnectionLog.record(
                            "Warp Identity: stage F — " + (if (finished) "engine exited without identity" else "timed out") +
                                "; " + targets.joinToString(" | ") { t -> targetState(t, masque) } + "; " + engineNote
                        )
                    } else ConnectionLog.record("Warp Identity: stage G ok — " + targets.joinToString(" | ") { t -> t.name + "=complete" })
                    break
                }
                val now = android.os.SystemClock.elapsedRealtime()
                if (now % 4000 < 500) {
                    ConnectionLog.record("Warp Identity: still working on $protocol… — " + targets.joinToString(" | ") { t -> targetState(t, masque) })
                }
                try { Thread.sleep(POLL_MS) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        } catch (e: Exception) { android.util.Log.w(TAG, "Warp identity fetcher crashed: " + e.message); ConnectionLog.record("Warp Identity: crashed — " + e.message) }
        finally {
            try { NativeCore.stop() } catch (_: Exception) {}
            try { Thread.sleep(300) } catch (_: InterruptedException) {}
            if (!wasRunning) try { IdentityProvisioner.releaseShardListener(startedOurselves = true) } catch (_: Exception) {}
            if (ok) { moved.forEach { backupOf(it).delete() }; android.util.Log.i(TAG, "new " + protocol + " identity saved via SHARD"); ConnectionLog.record("Warp Identity: " + protocol + " saved via Shard") }
            else { restore(moved); android.util.Log.w(TAG, protocol + " Warp identity via Shard failed — previous kept"); ConnectionLog.record("Warp Identity: " + protocol + " via Shard failed — previous kept") }
        }
        return ok
    }

    private fun awaitPort(port: Int, budgetMs: Long): Boolean { val dl = System.currentTimeMillis()+budgetMs; while(System.currentTimeMillis()<dl){ if(portAccepts(port, 300)) return true; Thread.sleep(100)}; return false }
    private fun portAccepts(port: Int, timeoutMs: Int): Boolean = try { java.net.Socket().use{ it.connect(java.net.InetSocketAddress("127.0.0.1", port), timeoutMs); true } } catch(_:Exception){ false }

    private fun buildEnvForShard(context: Context, norm: String, upstream: String): Map<String, String> {
        val protoForEnv = when (norm) {
            "mim", "masque-in-masque", "masque over masque" -> "mim"
            "masque" -> "masque"
            "gool", "wow", "warp-in-warp" -> "gool"
            else -> "wireguard"
        }
        // Same minimal construction as buildEnv, plus the SHARD upstream only.
        // A previous tunnel's env (NOIZE/SCAN/MTU/SNI/TLS) leaked into this job.
        val out = LinkedHashMap<String, String>()
        out["AETHER_CONFIG"] = File(context.filesDir, "aether.toml").absolutePath
        out["AETHER_PROTOCOL"] = protoForEnv
        out["AETHER_SOCKS"] = BIND
        out["AETHER_LOG_LEVEL"] = "info"
        out["AETHER_UPSTREAM"] = upstream
        // Registration-only via SHARD upstream: no tunnel/scan, just provision.
        out["AETHER_REGISTER"] = when (protoForEnv) { "mim" -> "mim"; "masque" -> "masque"; "gool" -> "gool"; else -> "wg" }
        // Consumer WARP only — no Zero Trust carry-over from a previous connect.
        return out
    }

    /**
     * Registration env is built MINIMAL, not derived from the last tunnel's
     * CoreConfig.env(). After a real connect the process env still carries the
     * tunnel's keys (AETHER_NOIZE, AETHER_SCAN, MTUs, SNI, TLS groups, STATS…)
     * because CoreConfig.applyEnv only clears a short clearIfAbsent list. Those
     * leftovers leaked into the AETHER_REGISTER job and the engine exited fast
     * without writing the sibling identity file — exactly the "works fresh,
     * fails after any connect" report (test 2). Registration needs no scan, so
     * a fresh minimal env is both correct and isolated: Warp Setting only,
     * no connect path touched. REVERT: rebuild these from CoreConfig.env.
     */
    private fun buildEnv(context: Context, norm: String): Map<String, String> {
        val protoForEnv = when (norm) {
            "mim", "masque-in-masque", "masque over masque" -> "mim"
            "masque" -> "masque"
            "gool", "wow", "warp-in-warp" -> "gool"
            else -> "wireguard"
        }
        val out = LinkedHashMap<String, String>()
        out["AETHER_CONFIG"] = File(context.filesDir, "aether.toml").absolutePath
        out["AETHER_PROTOCOL"] = protoForEnv
        out["AETHER_SOCKS"] = BIND
        out["AETHER_LOG_LEVEL"] = "info"
        // Quantum ECH: embedded key, API-only — same key the main connect uses
        // for Freedom; registration dials api.cloudflareclient.com over it.
        out["AETHER_API_ECH"] = EchEndpointRoster.freshApiEch(context) ?: ECH_EMBEDDED
        // Registration-only: no tunnel/scan, just provision via ECH.
        out["AETHER_REGISTER"] = when (protoForEnv) { "mim" -> "mim"; "masque" -> "masque"; "gool" -> "gool"; else -> "wg" }
        // Consumer WARP only — no Zero Trust carry-over from a previous connect.
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
