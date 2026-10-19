package com.msnguard.vpn.foxy

/** Minimal settings surface for the Foxy transport in MSN-GUARD. */
object FoxySettings {
    enum class TlsSplitMode { OFF, FIRST_BYTE, SNI }

    /** Persisted location choice for the Foxy dial (null = Automatic). */
    const val COUNTRY_PREF_KEY = "foxy_selected_country"

    fun selectedCountryCode(ctx: android.content.Context): String? =
        ctx.profiled().getString(COUNTRY_PREF_KEY, null)?.trim()?.takeIf { it.isNotBlank() }

    fun saveSelectedCountryCode(ctx: android.content.Context, code: String?) {
        ctx.profiled().edit()
            .putString(COUNTRY_PREF_KEY, code?.trim()?.takeIf { it.isNotBlank() })
            .apply()
    }

    // Defaults; wired to prefs later if the user needs them.
    fun tlsSplitMode(): TlsSplitMode = TlsSplitMode.OFF
    fun upstreamProxyEnabled(): Boolean = false
}

/** Fake-DNS range guard (ported helper): 100.64.0.0/10 netmask mapped range. */
object FoxySocksGuard {
    private val MAPDNS_NETWORK_BITS = 100L shl 24 or (64L shl 16)
    private val MAPDNS_NETMASK_BITS = 255L shl 24 or (192L shl 16)

    fun isFakeDnsAddress(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        var packed = 0L
        for (part in parts) {
            if (part.isEmpty() || part.length > 3) return false
            val octet = part.toIntOrNull() ?: return false
            if (octet !in 0..255) return false
            packed = (packed shl 8) or octet.toLong()
        }
        return (packed and MAPDNS_NETMASK_BITS) == MAPDNS_NETWORK_BITS
    }
}
