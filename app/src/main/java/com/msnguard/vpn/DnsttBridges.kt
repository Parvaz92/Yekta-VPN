package com.msnguard.vpn

import android.content.Context
import java.io.File

/** DNSTT bridge lines used by Orbot for Iran, with ordered resolver caching. */
internal object DnsttBridges {
    private const val BATCH_SIZE = 15
    private const val BATCH_OFFSET_PREF = "dnstt_bridge_batch_offset"
    const val PUBKEY_1 = "241169008830694749fe96bb070c4855c5bb5b9c47b3833ed7d88521ba30a43f"
    const val PUBKEY_2 = "a2fb71077eeaa54a02cda7a90be306af5d299ab21822a8b277d4eacbc9168631"
    const val DOMAIN_1 = "t.ruhnama.net"
    const val DOMAIN_2 = "t2.bypasscensorship.org"

    fun lines(context: Context, dataDir: File): List<String> {
        val selected = DnsttResolverScanner.prepare(context, dataDir)
        val resolvers = DnsttResolverScanner.cached(dataDir).ifEmpty {
            listOfNotNull(selected)
        }
        if (resolvers.isEmpty()) return emptyList()
        // Tor can dial at most 30 DNSTT bridge lines at a time. Keep the
        // discovery order, and advance to the next 15 resolvers on failure.
        val offset = context.profiled().getInt(BATCH_OFFSET_PREF, 0).coerceAtLeast(0)
        val normalizedOffset = offset.takeIf { it < resolvers.size } ?: 0
        if (normalizedOffset != offset) context.profiled().edit().putInt(BATCH_OFFSET_PREF, 0).apply()
        val batch = resolvers.drop(normalizedOffset).take(BATCH_SIZE)
        ConnectionLog.record("DNSTT Tor bridge batch: ${normalizedOffset + 1}..${normalizedOffset + batch.size} of ${resolvers.size} verified")
        return batch.flatMapIndexed { index, resolver ->
            val base = index * 2 + 1
            listOf(
                "dnstt 192.0.2.4:$base udp=$resolver:53 pubkey=$PUBKEY_1 domain=$DOMAIN_1",
                "dnstt 192.0.2.4:${base + 1} udp=$resolver:53 pubkey=$PUBKEY_2 domain=$DOMAIN_2",
            )
        }.take(30)
    }

    fun advanceAfterFailure(context: Context, dataDir: File) {
        val count = DnsttResolverScanner.cached(dataDir).size
        if (count == 0) return
        val next = (context.profiled().getInt(BATCH_OFFSET_PREF, 0).coerceAtLeast(0) + BATCH_SIZE) % count
        context.profiled().edit().putInt(BATCH_OFFSET_PREF, next).apply()
        ConnectionLog.record("DNSTT Tor bridge batch failed; next verified resolver offset $next/$count")
    }

    fun reset(context: Context) {
        context.profiled().edit().putInt(BATCH_OFFSET_PREF, 0).apply()
    }
}
