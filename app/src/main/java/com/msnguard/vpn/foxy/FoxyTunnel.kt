package com.msnguard.vpn.foxy

import android.content.Context
import com.msnguard.vpn.ConnectionLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Foxy transport manager — the app-layer engine behind MSN's FOXY method.
 *
 * Data plane (all app-side, no Rust core involvement):
 *   VpnService TUN → TunEngine (MSN's choice: Hev/Zeptun/Badvpn, untouched)
 *     → FoxySocksServer (127.0.0.1:SOCKS_PORT)
 *     → H2UpstreamSession (netty, ALPN h2, TLS to the Fastly edge)
 *     → HTTP CONNECT <target> with proxy-authorization Bearer <guardian JWT>
 *
 * Control plane: FxA login (email + password + emailed verification code,
 * HAWK-signed), Guardian proxy pass (JWT, auto-activation), server list from
 * Mozilla RemoteSettings, edge address resolved over DoH.
 *
 * Isolation contract: this object never touches CoreConfig, WarpIdentityFetcher,
 * ShardManager, or the aether engine. Revert = delete this package + the two
 * service/UI hooks.
 */
object FoxyTunnel {

    // 1819 warp core, 1820 chain, 1824 shard, 1826 warp exit, 1827 smart-dns,
    // 1839 identity bind. 1830 is free and reserved for us.
    const val SOCKS_PORT = 1830

    /** WireGuard-style ladder baseline MTU for the FOXY TUN interface. */
    const val TUN_MTU = 1400

    private const val TAG = "FoxyTunnel"

    @Volatile private var socks: LocalSocks5Server? = null
    @Volatile private var session: UpstreamSession? = null
    @Volatile private var proxyPass: ProxyPass? = null

    val isRunning: Boolean get() = socks != null

    /** Bytes moved through the tunnel since start (for the service's stats poll). */
    @Volatile var txBytes: Long = 0L
    @Volatile var rxBytes: Long = 0L

    fun tokenStore(context: Context) = FxoTokenStore(context)
    fun authRepo(context: Context) = FxaAuthRepository(tokenStore(context))

    /**
     * Sign-in state machine for the Foxy panel:
     *  - null        → not signed in, no pending session
     *  - "pending"   → login accepted, waiting for the emailed verification code
     *  - "active"    → tokens stored (session valid)
     */
    fun signInStatus(context: Context): String? {
        val store = tokenStore(context)
        if (store.pendingSessionToken != null) return "pending"
        if (store.hasStoredSession()) return "active"
        return null
    }

    /**
     * Start a login attempt. Returns "needs-code" (202 — email sent), "signed-in"
     * (FxA did not require a code and tokens are already stored), or THROWS with
     * the real FxA failure. A swallowed Result here previously mapped every
     * wrong-password / unreachable-server error to "signed in" — never do that.
     */
    suspend fun login(context: Context, email: String, password: String): String =
        withContext(Dispatchers.IO) {
            val repo = authRepo(context)
            val needed = repo.startLogin(email.trim(), password).getOrThrow()
            if (needed) "needs-code" else "signed-in"
        }

    /** Verify the emailed code and finish the login. */
    suspend fun verifyCode(context: Context, code: String): Unit =
        withContext(Dispatchers.IO) {
            val repo = authRepo(context)
            runCatching { repo.submitTwoFactorCode(code.trim()) }.getOrThrow()
        }

    /** Fresh tokens for connect-time use (silent refresh; may throw). */
    suspend fun ensureAccessToken(context: Context): RuntimeAuth =
        withContext(Dispatchers.IO) {
            val repo = authRepo(context)
            runCatching { repo.ensureFreshAccessToken() }.getOrThrow()
        }

    fun signOut(context: Context) {
        runCatching { tokenStore(context).clear() }
        ConnectionLog.record("Foxy: signed out — tokens cleared")
    }

    /**
     * Bring the data plane up. Blocking listeners already spin inside
     * [FoxyLocalSocksServer.start]; throws with the last error on failure.
     */
    suspend fun start(context: Context) = withContext(Dispatchers.IO) {
        if (isRunning) return@withContext
        FoxyTunnel.rxBytes = 0L
        FoxyTunnel.txBytes = 0L
        // While Foxy owns the device, mirror its WARN/ERROR/INFO into the
        // user-visible connection log — the failure reasons otherwise die in
        // logcat and the log goes dark between "connected" and teardown.
        FoxyLog.mirror = { tag, _, msg ->
            ConnectionLog.record("Foxy: [" + tag + "] " + msg.take(160))
        }
        ConnectionLog.record("Foxy: starting — refreshing FxA session…")
        val auth = ensureAccessToken(context)

        ConnectionLog.record("Foxy: fetching connection pass…")
        val guardian = GuardianClient()
        val pass = runCatching {
            guardian.fetchProxyPass(GUARDIAN_ENDPOINT_DEFAULT, auth.accessToken)
        }.recoverCatching { first ->
            if (first is TokenInvalidError) {
                ConnectionLog.record("Foxy: activating connection pass once…")
                runCatching { guardian.activateGuardian(GUARDIAN_ENDPOINT_DEFAULT, auth.accessToken) }
                guardian.fetchProxyPass(GUARDIAN_ENDPOINT_DEFAULT, auth.accessToken)
            } else {
                throw first
            }
        }.getOrThrow()
        proxyPass = pass
        ConnectionLog.record("Foxy: pass acquired (lifetime noted)")

        val countries = ServerListClient(context)
            .fetchCountries()
        // Location choice from the Foxy page's Server picker (null = Automatic,
        // which keeps the historic first-country behaviour). A saved code that
        // the refreshed server list no longer carries must NOT silently fall
        // back to another country — the user asked for that exit, so fail loudly.
        val chosen = FoxySettings.selectedCountryCode(context)
            ?.takeIf { code -> countries.any { it.code.equals(code, ignoreCase = true) } }
        val candidates = ServerListClient.candidatesForCountry(
            countries,
            chosen ?: countries.firstOrNull()?.code ?: "",
        )
        if (candidates.isEmpty()) {
            if (chosen != null) {
                error("Foxy: no candidate in the selected country ($chosen) — pick a different server on the Foxy page")
            }
            error("Foxy: no reachable server found — try again later")
        }
        ConnectionLog.record(
            "Foxy: ${candidates.size} server candidate(s) in " +
                (chosen ?: countries.firstOrNull()?.code ?: "?"),
        )

        // The first candidate in the Mozilla list is often one the networked
        // device cannot reach at all (the user's log: tn hit `No reachability
        // after 15 pb(s)`), so walk the list until a session actually binds.
        var lastErr: Exception? = null
        for (cand in candidates) {
            try {
                val edge = EdgeAddressResolver.resolve(cand.host, listOf("1.1.1.1", "8.8.8.8"))
                ConnectionLog.record("Foxy: dialing ${cand.host}:${cand.port}")
                val s = H2UpstreamSession(
                    upstreamHost = cand.host,
                    upstreamPort = cand.port,
                    bearerToken = pass.token,
                    edgeAddress = edge,
                )
                s.connect()
                session = s

                val srv = LocalSocks5Server(
                    bindAddress = "127.0.0.1",
                    port = SOCKS_PORT,
                    rejectFakeDnsAddresses = true,
                    dohUrl = null,
                    sessionProvider = { session },
                ) {
                    ConnectionLog.record("Foxy: upstream unhealthy — reconnecting")
                }
                srv.start()
                socks = srv
                ConnectionLog.record("Foxy: tunnel up — SOCKS on 127.0.0.1:$SOCKS_PORT")
                return@withContext
            } catch (e: Exception) {
                lastErr = e
                ConnectionLog.record("Foxy: dial to ${cand.host} failed — ${e.message ?: "unknown"}")
            }
        }
        stop()
        throw lastErr ?: IllegalStateException("Foxy: could not reach any server")
    }

    fun stop() {
        runCatching { socks?.stop().also { socks = null } }
        runCatching { session?.close().also { session = null } }
        FoxyLog.mirror = null
        ConnectionLog.record("Foxy: stopped")
    }

    /** Log-location helper for the in-panel vault path (unused external state). */
    fun stateDir(context: Context): File = context.filesDir
}
