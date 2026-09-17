package com.msnguard.vpn

import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.security.SecureRandom
import android.util.Base64

/**
 * Encrypts the exported connection log.
 *
 * The log carries the transport's full description: engine, port layout, pool
 * sizes, node identities and the channel handles the publisher ships in node
 * labels. The [LogRedactor] tokenises the parts that identify *users*, but the
 * rest is still a wiring diagram of the bypass, and it is attached to a message
 * the user sends over Telegram. Encrypting the export keeps that readable only
 * to whoever holds the key.
 *
 * AES-256-GCM, one key for every build, one random IV per line batch. The key
 * is fixed in source — it is shipped in the APK, so it is not a secret from
 * anyone who unpacks the app. What it does buy is that a log forwarded in
 * public does not read itself to whoever happens to see it, and that the user
 * (or any tool handed the key file) can always decrypt what they sent. This is
 * the same honesty as [LogRedactor.DIGEST_KEY]: the protection is against the
 * casual reader, not against a determined reverse engineer.
 *
 * Every encrypted export starts with the header line [MAGIC] so a reader can
 * tell an encrypted export from a plain one without guessing.
 */
object LogCipher {

    /** Fixed key, 256 bits. Ship it verbatim in the key file. */
    private const val KEY_MATERIAL = "MSN-GUARD-log-cipher-v2.2.0-7a3f9c1e"

    private const val MAGIC = "MSN-GUARD-ENC-V1"

    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    private val key: SecretKeySpec by lazy {
        val digest = MessageDigest.getInstance("SHA-256")
        SecretKeySpec(digest.digest(KEY_MATERIAL.toByteArray(Charsets.UTF_8)), "AES")
    }

    /**
     * Encrypts [plain], returning a self-describing block: the magic header,
     * the base64 IV and the base64 ciphertext on separate lines.
     */
    fun encrypt(plain: String): String {
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return buildString {
            append(MAGIC).append('\n')
            append(Base64.encodeToString(iv, Base64.NO_WRAP)).append('\n')
            append(Base64.encodeToString(ct, Base64.NO_WRAP))
        }
    }

    /**
     * Decrypts a block produced by [encrypt]. Returns null on anything that is
     * not a recognised block — a tampered or truncated log is reported, never
     * partially read out.
     */
    fun decrypt(block: String): String? {
        val parts = block.trim().split('\n')
        if (parts.size != 3 || parts[0] != MAGIC) return null
        return runCatching {
            val iv = Base64.decode(parts[1], Base64.NO_WRAP)
            val ct = Base64.decode(parts[2], Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            String(cipher.doFinal(ct), Charsets.UTF_8)
        }.getOrNull()
    }

    /** True for any text that begins with an encrypted export's header. */
    fun isEncrypted(text: String): Boolean = text.trimStart().startsWith(MAGIC)

    /**
     * The human key file. Written so the user can decrypt their own log without
     * this app, and so any tool given the file can too. Every line is plain
     * English explaining exactly what it is and how to use it.
     */
    fun writeKeyFile(dest: File) {
        dest.writeText(
            """
MSN-GUARD · Log Key
===================

This file decrypts connection logs exported by MSN-GUARD ${appVersionReadable()}.

What the log is
---------------
When a user taps "Send log", the app exports everything it recorded: engine
choices, port layout, node identities, and the wiring of the bypass. The export
is encrypted with AES-256-GCM so that it does not read itself to whoever sees
the message it was attached to. This key reverses that.

The key
-------
KEY MATERIAL (hex):
${key.encoded.joinToString("") { "%02x".format(it) }}

Algorithm:    AES-256-GCM (12-byte IV, 128-bit tag)
Key derived:  SHA-256 of the literal string below
Key string:   $KEY_MATERIAL

How to decrypt
--------------
An encrypted log looks like three lines:

  MSN-GUARD-ENC-V1
  <base64 IV>
  <base64 ciphertext>

The first line is the marker; the second is the 12-byte IV; the third is the
ciphertext WITH the 16-byte GCM authentication tag appended to it (base64, no
line breaks). The tag is the last 16 bytes of that third blob — GCM needs it
separately, so split it off before decrypting.

In Python, with pycryptodome installed (pip install pycryptodome):

  from Crypto.Cipher import AES
  import base64, hashlib

  key = hashlib.sha256("$KEY_MATERIAL".encode("utf-8")).digest()
  lines = open("log.txt", "r").read().split("\\n")
  iv = base64.b64decode(lines[1])
  blob = base64.b64decode(lines[2])
  ct, tag = blob[:-16], blob[-16:]
  plain = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
  print(plain.decode("utf-8"))

This is tested against the app's own output. The last line above will raise
if the log was tampered with — that is the authentication tag doing its job,
and it means the log is not trustworthy rather than partly readable.

The same in a shell with openssl is not practical: OpenSSL's CLI wants the tag
in a separate -inkey argument and does not accept the appended form. Use the
Python path above.

Notes
-----
- The key is also present inside the APK, so it protects the log from the casual
  reader of a forwarded message, not from a reverse engineer. That is the
  intended threat model: the export is opaque in public, readable to whoever
  holds this file.
- One key serves every log from this version. Logs from an older plain export
  have no marker and are already readable.
- Decryption either succeeds completely or fails — the authentication tag means
  a tampered log is rejected outright rather than partially read.
""".trimIndent() + "\n"
        )
    }

    /** Version string for the key file's header; never blank. */
    private fun appVersionReadable(): String {
        val ctx = AppLanguage.appContext ?: return "this version"
        return runCatching {
            @Suppress("DEPRECATION")
            "v" + ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName
        }.getOrDefault("this version")
    }
}
