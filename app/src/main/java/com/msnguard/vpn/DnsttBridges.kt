package com.msnguard.vpn

import android.content.Context
import java.io.File

/** DNSTT bridge lines used by Orbot for Iran, with ordered resolver caching. */
internal object DnsttBridges {
    private const val PUBKEY_1 = "241169008830694749fe96bb070c4855c5bb5b9c47b3833ed7d88521ba30a43f"
    private const val PUBKEY_2 = "a2fb71077eeaa54a02cda7a90be306af5d299ab21822a8b277d4eacbc9168631"
    private const val FP_1 = "A998F319ADB60EE344540EC4B21524CC484F96BE"
    private const val FP_2 = "80EEFA4F4875ED2B7B5A86DF2D7588AD32E29F15"

    fun lines(context: Context, dataDir: File): List<String> {
        val selected = DnsttResolverScanner.prepare(context, dataDir)
        val resolvers = DnsttResolverScanner.cached(dataDir).ifEmpty {
            listOfNotNull(selected)
        }
        if (resolvers.isEmpty()) {
            return listOf(
                "dnstt 192.0.2.4:1 $FP_1 doh=https://dns.google/dns-query pubkey=$PUBKEY_1 domain=t.ruhnama.net",
                "dnstt 192.0.2.4:2 $FP_2 doh=https://dns.google/dns-query pubkey=$PUBKEY_2 domain=t2.bypasscensorship.org",
            )
        }
        return resolvers.flatMapIndexed { index, resolver ->
            val base = index * 2 + 1
            listOf(
                "dnstt 192.0.2.4:$base $FP_1 udp=$resolver:53 pubkey=$PUBKEY_1 domain=t.ruhnama.net",
                "dnstt 192.0.2.4:${base + 1} $FP_2 udp=$resolver:53 pubkey=$PUBKEY_2 domain=t2.bypasscensorship.org",
            )
        }.take(30)
    }
}
