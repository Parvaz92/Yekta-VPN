package com.msnguard.vpn

import java.net.HttpURLConnection
import java.net.URL

/**
 * Geolocates a tunnel exit address, outside the UI.
 *
 * Extracted from MainActivity's private `fetchCountryFor` for one reason: the
 * service now needs the same answer. When the user asks for a preferred exit
 * country, the service — not the activity — decides whether the exit it just
 * measured matches, because the rotation must fire even when no activity is
 * alive (tile connects, screen off). The tile case is not hypothetical: the
 * service is the only thing running in it.
 *
 * The URLs, and the property they share, are unchanged from the activity's:
 * both are HTTPS, keyless and Cloudflare-fronted (so reachable from Iran), and
 * both were verified from an uncensored host returning IR for the real WARP
 * exits 104.28.214.161/167. The question is a property of the ADDRESS, not of
 * the route the query takes — that is the whole reason the service can ask it
 * over its carrier-excluded link while the browser it describes rides the TUN.
 *
 * Never called on the main thread: each request is up to
 * [TIMEOUT_MS] and the service asks two hosts in the worst case.
 */
object ExitGeo {

    /** `%s` is the address to geolocate. */
    private val LOOKUP_URLS = arrayOf(
        "https://get.geojs.io/v1/ip/country/%s.json",
        "https://ipwho.is/%s?fields=country_code",
    )

    /** Matches `"country":"IR"` and `"country_code":"IR"` alike. */
    private val CODE_JSON = Regex("\"country(?:_code)?\"\\s*:\\s*\"([A-Za-z]{2})\"")

    private const val TIMEOUT_MS = 5_000

    /**
     * Two-letter ISO code of [ip], uppercase, or null when nobody answered.
     *
     * Null — not a best guess — on failure: an unknown country must leave the
     * tunnel alone (a rotation on a wrong "not GB" verdict would churn
     * endpoints for nothing), and an empty string cannot be compared against a
     * preference.
     */
    fun countryOf(ip: String): String? {
        if (ip.isBlank()) return null
        for (template in LOOKUP_URLS) {
            try {
                val connection = (URL(template.format(ip)).openConnection() as HttpURLConnection).apply {
                    connectTimeout = TIMEOUT_MS
                    readTimeout = TIMEOUT_MS
                    requestMethod = "GET"
                }
                try {
                    if (connection.responseCode !in 200..299) continue
                    val body = connection.inputStream.bufferedReader().use { it.readText() }
                    CODE_JSON.find(body)?.groupValues?.get(1)?.let { return it.uppercase() }
                } finally {
                    connection.disconnect()
                }
            } catch (_: Throwable) {
                // Try the next endpoint.
            }
        }
        return null
    }
}
