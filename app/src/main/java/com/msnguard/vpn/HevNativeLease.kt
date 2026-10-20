package com.msnguard.vpn

/**
 * Who owns libhev's native tunnel in this process.
 *
 * libhev keeps exactly ONE native tunnel per process, so the shared
 * [HevEngine] (used by the WARP/MASQUE/Psiphon/Shard/Tor paths) and the FOXY
 * transport's own engine can never run at the same time. Without a record of
 * ownership, a teardown on one side tears down the other: `HevEngine.stop()`
 * would stop the native thread that FOXY had started, and the shared
 * engine's `start()` would short-circuit on a native instance it does not own.
 *
 * This object is the record. It holds a tag, not state: the native thread
 * itself is still libhev's, and only the owner is allowed to stop it.
 *
 * Neutral on purpose — it lives next to the shared engine so neither side has
 * to know about the other one's class.
 */
object HevNativeLease {

    /** The shared engine (every transport that is not FOXY). */
    const val SHARED = "shared"

    /** The FOXY transport's own engine. */
    const val FOXY = "foxy"

    @Volatile private var owner: String? = null

    /** The tag that currently owns the native thread, or null if nobody does. */
    val currentOwner: String? get() = owner

    /** Take ownership. Used when a side starts the native thread. */
    fun claim(tag: String) {
        owner = tag
    }

    /** Give up ownership, but only if this side still holds it. */
    fun release(tag: String) {
        if (owner == tag) owner = null
    }

    /** True when [tag] is the side that started the native thread. */
    fun isOwnedBy(tag: String): Boolean = owner == tag
}
