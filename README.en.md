<div align="center">

<img src="docs/logo.png" width="150" alt="MSN-GUARD">

# MSN-GUARD

**A device-wide Android tunnel for difficult networks**

[![Build](https://img.shields.io/github/actions/workflow/status/mbm110/MSN-GUARD/build.yml?branch=master&style=for-the-badge&label=build)](https://github.com/mbm110/MSN-GUARD/actions)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3A4FB0?style=for-the-badge&logo=android&logoColor=white)](https://github.com/mbm110/MSN-GUARD)
[![License](https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge)](LICENSE)
[![Transports](https://img.shields.io/badge/transports-7-1f6f4a?style=for-the-badge)](#connection-methods)

**English** · [فارسی](README.md)

</div>

---

## A quick look

<p align="center">
  <img src="docs/msn-guard-dashboard.jpg" width="380" alt="MSN-GUARD dashboard showing a connected WireGuard session, live traffic statistics, transport choices, and a chained Psiphon over WARP status">
</p>

MSN-GUARD is built for people who need a full-device connection on networks where a single tunnel is not enough. The app owns Android's `VpnService` and TUN interface, so traffic from every application can follow the selected route without per-app proxy settings.

The interface keeps the important state visible: session time, latency, traffic, speed, exit location, active method, and the health of a chained route. The details that make a route survive a particular network remain intentionally quiet; this page describes the system without publishing its sensitive operating recipe.

## What is inside

- **Seven connection methods:** WireGuard, MASQUE, WoW, Psiphon, Tor, Foxy, and SHARD.
- **Several transport shapes:** direct WARP paths, nested WARP, CDN-backed Psiphon, Tor bridges, Foxy sessions, and SHARD node pools.
- **One-tap connection:** endpoint selection, identity retrieval, MTU choice, recovery, and post-connect verification are coordinated by the app.
- **Real connection checks:** a handshake alone is not treated as success; the tunnel must carry traffic.
- **Endpoint discovery:** normal and Ptech scanner modes, address-family choices, bounded probing, and data-plane checks.
- **Automatic MTU selection:** each supported method can be measured before connection and kept consistent across the Android TUN and native engine.
- **Multiple TUN engines:** BadVPN/lwIP, Hev, and Zeptun are available for the paths that need a userspace packet bridge.
- **Identity Vault:** WARP and MASQUE identities can be obtained through more than one route and shown per method in settings.
- **Profiles:** connection, performance, routing, DNS, and transport preferences can be kept in named profiles.
- **Tor integration:** direct Tor, bridges, CDN-style paths, Snowflake, Meek, and Tor-over-WARP are managed inside the same Android VPN service.
- **Psiphon integration:** automatic transport selection and CDN fronting can be used alone or inside WARP.
- **Live diagnostics:** connection logs, exit information, counters, session timer, and health state are available while the tunnel is running.
- **Languages:** English, فارسی, 简体中文, and Русский.
- **Privacy controls:** split tunnelling, DNS control, kill switch behavior, and protected outbound sockets help prevent routing loops and accidental leaks.

## Connection methods

| Method | Role in the app |
|---|---|
| **WireGuard** | Direct WARP transport for networks where UDP remains usable. |
| **MASQUE** | WARP over HTTP/3 with endpoint discovery and data-plane verification. |
| **WoW** | A nested WARP path for networks where an outer route can carry an inner one. |
| **Psiphon** | A resilient path with automatic strategy selection, optional CDN fronting, and WARP chaining. |
| **Tor** | Direct Tor or bridge-based access, including Meek and Snowflake paths. |
| **Foxy** | A separate account-backed transport with its own edge selection, TLS handling, and userspace bridge. |
| **SHARD** | A node-pool path with endpoint rotation, health checks, and a dedicated packet front. |

The names are intentionally simple. The work behind them is not: each method has its own lifecycle, failure model, MTU behavior, and verification path.

## Architecture

```text
Android applications
        |
        v
Android VpnService + TUN
        |
        +--> BadVPN/lwIP, Hev, or Zeptun packet engine
        |
        +--> Kotlin transport supervision and health checks
        |
        +--> Rust core: WARP, MASQUE, WireGuard, discovery, and packet paths
        |
        +--> Psiphon / Tor / Foxy / SHARD integrations
        |
        v
Selected upstream route
```

The Kotlin layer owns Android lifecycle, permissions, TUN setup, settings, profiles, logs, and service recovery. The Rust core handles the low-level WARP family and its native network work. Other transports attach through controlled local interfaces while the app keeps one Android VPN owner.

## Discovery, MTU, and verification

MSN-GUARD treats connection as a measured process. Depending on the selected method, it can discover candidate endpoints, test more than one address family, apply a bounded probe budget, choose an MTU, and verify that useful bytes cross the tunnel. A server or gateway that merely accepts a handshake is not enough.

The same principle is used by the automatic fallback logic: a route can be demoted when its listener is alive but its data path is empty. Cached choices help the next connection start quickly, while fresh checks remain available when the network changes.

## Identity and profiles

WARP and MASQUE credentials are kept on the device and are associated with their method. Identity retrieval can use the configured relay path or the fallback route supported by the app. The settings view reads the stored identity state so a credential obtained during a home-screen connection is reflected in the corresponding card.

Named profiles make it possible to keep different combinations of transport, scanner, MTU, DNS, chaining, exit, and performance preferences without rebuilding them by hand.

## Install

Download signed APKs from [Releases](https://github.com/mbm110/MSN-GUARD/releases). GitHub Actions also provides build artifacts for development testing.

Android 8.0 / API 26 or newer is required. On first use, Android will ask for VPN permission. The project builds separate ARM variants as well as the universal and emulator packages used for testing.

## Build

Builds are produced by GitHub Actions. The native core, Android client, and bundled transport components are assembled per ABI by the workflow in [`.github/workflows/`](.github/workflows/).

The repository contains Kotlin, Rust, and native packet-engine code. Vendored components retain their own licenses; see [LICENSE](LICENSE) and the notices in the relevant directories before redistributing a modified build.

## Security and disclosure

The connection parameters, endpoint rankings, timing choices, and other network-specific details are deliberately not documented here. They change with the network and publishing them would make the useful parts easier to copy and block.

Do not put credentials, identity material, private keys, or user traffic in issues. For security reports, use the private process described in [SECURITY.md](SECURITY.md).

## Support the project

If MSN-GUARD is useful to you, donations help cover development and testing. Always select the correct network before sending funds.

```text
Ethereum Chain
0xA9e165Db72a6f1B3261dfcFb7cc9ADD725Ea2f25

Bitcoin
bc1q4ntxszj643n0ujj3uuncljk8uyprug4swprxlg

Tron Chain
TN58EHrD9AvtVEx4FSka5kitwpgXdXbri9

Solana Chain
3wPEfTm1bCbrU9aqie7xMgAXJK1qXGktRn2yjtjb6LPt
```

## License

MSN-GUARD is released under [GNU AGPL-3.0](LICENSE). Bundled components are distributed under their respective licenses, including the licenses documented for quiche, BadVPN, lwIP, Psiphon, Tor, and lyrebird.

<div align="center">

**Developed and maintained by [mbm110](https://github.com/mbm110)**

</div>
