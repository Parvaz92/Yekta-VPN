package com.msnguard.vpn

import android.content.Context
import java.io.File

/** DNSTT bridge lines used by Orbot for Iran, with ordered resolver caching. */
internal object DnsttBridges {
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
        // Unique placeholder ports identify each bridge. Omit repeated relay
        // fingerprints: Tor deduplicates bridges with the same fingerprint.
        return resolvers.flatMapIndexed { index, resolver ->
            val base = index * 2 + 1
            listOf(
                "dnstt 192.0.2.4:$base udp=$resolver:53 pubkey=$PUBKEY_1 domain=$DOMAIN_1",
                "dnstt 192.0.2.4:${base + 1} udp=$resolver:53 pubkey=$PUBKEY_2 domain=$DOMAIN_2",
            )
        }.take(30)
    }
}
