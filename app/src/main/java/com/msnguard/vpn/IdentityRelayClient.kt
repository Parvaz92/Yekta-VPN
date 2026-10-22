package com.msnguard.vpn

import android.content.Context
import android.util.Base64
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.Date
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.json.JSONObject
import java.io.StringWriter
import java.math.BigInteger

/** Worker-only account enrollment. The injected HMAC is an abuse barrier, not anti-clone. */
object IdentityRelayClient {
    const val RELAY_A = "https://msnguard-identity-relay-a.msnguard-edge-one.workers.dev"
    const val RELAY_B = "https://msnguard-identity-relay-b.msnguard-edge-two.workers.dev"
    const val REGISTER_PATH = "/v0a4471/reg"
    const val ENROLL_PATH_PREFIX = "/v0a4471/reg/"
    const val AUTH_TIMESTAMP = "X-MSN-Timestamp"
    const val AUTH_NONCE = "X-MSN-Nonce"
    const val AUTH_SIGNATURE = "X-MSN-Signature"
    const val AUTH_ALGORITHM = "HmacSHA256"
    const val CONNECT_TIMEOUT_MS = 8_000
    const val READ_TIMEOUT_MS = 16_000
    val ENDPOINT_LADDER = listOf(RELAY_A, RELAY_B)

    data class Outcome(val success: Boolean, val error: String)
    private data class Hop(val response: JSONObject, val wgPrivate: ByteArray, val cert: String, val key: String, val issued: Long)

    fun provision(context: Context, protocol: String, cancelled: () -> Boolean = { false }): Outcome {
        if (BuildConfig.IDENTITY_RELAY_HMAC_B64.isEmpty()) return Outcome(false, "relay auth not configured")
        val names = when (protocol.lowercase()) {
            "mim" -> listOf("masque", "masque-secondary")
            "masque" -> listOf("masque")
            "gool", "wow" -> listOf("wireguard", "secondary")
            "wireguard", "wg" -> listOf("wireguard")
            else -> return Outcome(false, "unknown identity method")
        }
        val prepared = mutableListOf<Pair<File, String>>()
        val base = File(context.filesDir, "aether.toml")
        for (name in names) {
            if (cancelled()) return Outcome(false, "cancelled")
            val file = when (name) {
                "masque" -> File(context.filesDir, "aether-masque.toml")
                "masque-secondary" -> File(context.filesDir, "aether-masque-secondary.toml")
                "secondary" -> File(context.filesDir, "aether-secondary.toml")
                else -> base
            }
            if (IdentityProvisioner.validIdentityFile(file, name.startsWith("masque"))) continue
            var failure = "relay unavailable"
            var text: String? = null
            for (endpoint in ENDPOINT_LADDER) {
                if (cancelled()) return Outcome(false, "cancelled")
                try {
                    val hop = enroll(endpoint, name.startsWith("masque"))
                    text = IdentityProvisioner.relayToml(hop.response, hop.wgPrivate, hop.cert, hop.key, hop.issued)
                    if (text == null) failure = "invalid relay account response"
                    if (text != null) break
                } catch (e: Exception) {
                    failure = e.message?.take(100) ?: e.javaClass.simpleName
                }
            }
            if (text == null) return Outcome(false, failure)
            prepared += file to text
        }
        if (cancelled()) return Outcome(false, "cancelled")
        return if (IdentityProvisioner.installRelayedFiles(prepared)) Outcome(true, "identity stored")
        else Outcome(false, "could not store identity")
    }

    private fun enroll(endpoint: String, masque: Boolean): Hop {
        val wgKey = X25519PrivateKeyParameters(SecureRandom())
        val wgPublic = ByteArray(32).also { wgKey.generatePublicKey().encode(it, 0) }
        val privateBytes = ByteArray(32).also { wgKey.encode(it, 0) }
        val body = JSONObject().apply {
            put("key", Base64.encodeToString(wgPublic, Base64.NO_WRAP))
            put("install_id", "")
            put("fcm_token", "")
            put("tos", java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", java.util.Locale.US).format(Date()))
            put("model", android.os.Build.MODEL)
            put("serial_number", java.util.UUID.randomUUID().toString().replace("-", "").take(16))
            put("os_version", "")
            put("key_type", "curve25519")
            put("tunnel_type", "wireguard")
            put("locale", java.util.Locale.getDefault().toString())
        }.toString()
        val account = request(endpoint, "POST", REGISTER_PATH, body, null)
        val deviceId = account.optString("id").takeIf { it.matches(Regex("[A-Za-z0-9_-]+")) }
            ?: error("invalid device id")
        val token = account.optString("token").takeIf { it.isNotEmpty() } ?: error("missing token")
        // A newly registered WARP account can handshake without carrying traffic
        // until warp_enabled is set. MASQUE needs its own authenticated key PATCH.
        if (!account.optBoolean("warp_enabled", false)) {
            val enabled = request(endpoint, "PATCH", ENROLL_PATH_PREFIX + deviceId,
                JSONObject().put("warp_enabled", true).toString(), token)
            if (!enabled.optBoolean("warp_enabled", false)) error("WARP was not enabled")
        }
        if (!masque) return Hop(account, privateBytes, "", "", 0)
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"), SecureRandom())
        }.generateKeyPair()
        val issued = System.currentTimeMillis() / 1000
        val name = X500Name("CN=$deviceId")
        val builder = JcaX509v3CertificateBuilder(name, BigInteger(128, SecureRandom()),
            Date((issued - 60) * 1000), Date((issued + 365L * 86400) * 1000), name, pair.public)
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(pair.private)
        val certificate = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        val update = JSONObject().apply {
            put("key", Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP))
            put("key_type", "${KEY_TYPE_MASQUE}")
            put("tunnel_type", "${TUNNEL_TYPE_MASQUE}")
        }.toString()
        request(endpoint, "PATCH", ENROLL_PATH_PREFIX + deviceId, update, token)
        return Hop(account, privateBytes, pem(certificate), privatePem(pair.private.encoded), issued)
    }

    private const val KEY_TYPE_MASQUE = "secp256r1"
    private const val TUNNEL_TYPE_MASQUE = "masque"

    private fun privatePem(encoded: ByteArray): String = StringWriter().also { writer ->
        PemWriter(writer).use { it.writeObject(PemObject("PRIVATE KEY", encoded)) }
    }.toString()

    private fun pem(value: Any): String = StringWriter().also { writer ->
        JcaPEMWriter(writer).use { it.writeObject(value) }
    }.toString()

    private fun request(endpoint: String, method: String, path: String, body: String, token: String?): JSONObject {
        val timestamp = System.currentTimeMillis().toString()
        val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val signatureInput = "$method\n$path\n$timestamp\n$nonce\n$body"
        val mac = Mac.getInstance(AUTH_ALGORITHM).apply {
            init(SecretKeySpec(Base64.decode(BuildConfig.IDENTITY_RELAY_HMAC_B64, Base64.DEFAULT), AUTH_ALGORITHM))
        }
        val signature = mac.doFinal(signatureInput.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val connection = URL(endpoint + path).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = method
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("User-Agent", "WARP for Android")
            connection.setRequestProperty("CF-Client-Version", "a-6.35-4471")
            connection.setRequestProperty(AUTH_TIMESTAMP, timestamp)
            connection.setRequestProperty(AUTH_NONCE, nonce)
            connection.setRequestProperty(AUTH_SIGNATURE, signature)
            if (token != null) connection.setRequestProperty("Authorization", "Bearer $token")
            connection.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            if (connection.responseCode !in 200..299) error("relay HTTP ${connection.responseCode}")
            return JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
        } finally { connection.disconnect() }
    }
}
