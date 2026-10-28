package com.msnguard.vpn

/** DNSTT bridge lines used by Orbot for Iran. */
internal object DnsttBridges {
    private const val DOH = "doh=https://dns.google/dns-query"
    private const val PUBKEY_1 = "241169008830694749fe96bb070c4855c5bb5b9c47b3833ed7d88521ba30a43f"
    private const val PUBKEY_2 = "a2fb71077eeaa54a02cda7a90be306af5d299ab21822a8b277d4eacbc9168631"

    fun lines(): List<String> = listOf(
        "dnstt 192.0.2.4:1 A998F319ADB60EE344540EC4B21524CC484F96BE $DOH pubkey=$PUBKEY_1 domain=t.ruhnama.net",
        "dnstt 192.0.2.4:2 80EEFA4F4875ED2B7B5A86DF2D7588AD32E29F15 $DOH pubkey=$PUBKEY_2 domain=t2.bypasscensorship.org",
    )
}
