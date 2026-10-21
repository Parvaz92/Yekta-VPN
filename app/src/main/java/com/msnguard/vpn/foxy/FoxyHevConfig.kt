package com.msnguard.vpn.foxy

import android.content.Context
import java.io.File

/**
 * Hev (hev-socks5-tunnel) configuration for the FOXY transport.
 *
 * This is a port of the reference project's HevSocks5TunnelConfig, kept
 * inside the foxy package on purpose: the shared `HevEngine` object that
 * every other transport uses writes a different YAML into
 * `filesDir/hev/hev-<port>.yml`, and the two must never influence each
 * other. FOXY gets its own file under `filesDir/foxy/`, its own values and
 * its own lifecycle.
 *
 * Why the values differ from the shared engine's:
 *
 *  - `read-write-timeout: 60000` (what the shared engine writes) sets the
 *    TCP idle timeout of every tunnelled connection to 60 s. The reference
 *    uses 300 s for TCP and 60 s for UDP, which is what a long-lived
 *    Telegram/WhatsApp socket needs; the 60 s TCP ceiling silently
 *    reaps idle connections that the tunnel is supposed to keep.
 *  - `connect-timeout: 20000` instead of 5000 — the reference's value, and
 *    the only one that survives a slow carrier link.
 *  - the reference's buffer sizes, `max-session-count: 0` and
 *    `limit-nofile: 65535` are all spelled out. The bundled hev-config.c
 *    understands every one of these keys (task-stack-size, tcp-buffer-size,
 *    udp-recv-buffer-size, udp-copy-buffer-nums, max-session-count,
 *    connect-timeout, tcp-read-write-timeout, udp-read-write-timeout,
 *    limit-nofile) — this is the same set the reference ships.
 *  - `tunnel.ipv4` is written as a bare address like the reference does.
 *    In VPN mode (external TUN fd) hev ignores it anyway, but the shared
 *    engine's `198.18.0.1/32` form is not even a valid address string.
 */
object FoxyHevConfig {

    /** Own directory — the shared engine's filesDir/hev/ stays untouched. */
    private const val FILE_DIR = "foxy"

    /**
     * Synthetic address Hev's mapdns answers on. The FOXY TUN publishes this
     * as the interface's only resolver, and Hev maps it back to domain names.
     */
    const val MAPDNS_ADDRESS = "198.18.0.2"

    private const val MAPDNS_PORT = 53

    private const val MAPDNS_NETWORK = "100.64.0.0"

    private const val MAPDNS_NETMASK = "255.192.0.0"

    private const val MAPDNS_CACHE_SIZE = 10_000

    private const val TUNNEL_ICMP_MODE = "reply"

    private const val TUN_ADDRESS = "10.8.0.2"

    private const val CONNECT_TIMEOUT_MS = 20_000

    private const val TCP_READ_WRITE_TIMEOUT_MS = 300_000

    private const val UDP_READ_WRITE_TIMEOUT_MS = 60_000

    private const val TCP_BUFFER_SIZE_BYTES = 65_536

    private const val TASK_STACK_SIZE_BYTES = 86_016

    private const val UDP_RECV_BUFFER_SIZE_BYTES = 524_288

    private const val UDP_COPY_BUFFER_NUMS = 16

    private const val MAX_SESSION_COUNT = 0

    private const val LIMIT_NOFILE = 65_535

    /**
     * Write the FOXY Hev config and return the file.
     *
     * @param socksPort the local SOCKS5 listener Hev must forward into.
     */
    fun write(context: Context, socksPort: Int, mtu: Int): File {
        val yaml = """
            tunnel:
              mtu: $mtu
              ipv4: '$TUN_ADDRESS'
              icmp: '$TUNNEL_ICMP_MODE'
            socks5:
              port: $socksPort
              address: '127.0.0.1'
              udp: 'udp'
            mapdns:
              address: '$MAPDNS_ADDRESS'
              port: $MAPDNS_PORT
              network: '$MAPDNS_NETWORK'
              netmask: '$MAPDNS_NETMASK'
              cache-size: $MAPDNS_CACHE_SIZE
            misc:
              task-stack-size: $TASK_STACK_SIZE_BYTES
              connect-timeout: $CONNECT_TIMEOUT_MS
              tcp-read-write-timeout: $TCP_READ_WRITE_TIMEOUT_MS
              udp-read-write-timeout: $UDP_READ_WRITE_TIMEOUT_MS
              tcp-buffer-size: $TCP_BUFFER_SIZE_BYTES
              udp-recv-buffer-size: $UDP_RECV_BUFFER_SIZE_BYTES
              udp-copy-buffer-nums: $UDP_COPY_BUFFER_NUMS
              max-session-count: $MAX_SESSION_COUNT
              limit-nofile: $LIMIT_NOFILE
              log-level: 'warn'
            """.trimIndent() + "\n"

        val dir = File(context.filesDir, FILE_DIR).apply { mkdirs() }
        val file = File(dir, "hev-foxy-$socksPort.yml")
        file.writeText(yaml)
        return file
    }
}
