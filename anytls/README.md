# anytls-client — MSN-GUARD SHARD sidecar

Production client for the AnyTLS protocol, built for MSN-GUARD's SHARD
transport. Vendored from the reference implementation
([anytls-go](https://github.com/anytls/anytls-go), commit `fd6167a`) with a
hardened main: real TLS verification against the Android system trust store
(the reference sample ships `InsecureSkipVerify: true`), a per-node runtime
config format, and Android-only build constraints.

The protocol library (`proxy/`, `util/`) is upstream code, unchanged; all
changes live in `cmd/anytls-client/`.

## Why a sidecar binary and not sing-box

Measured, not estimated (see the project's AnyTLS feasibility note):
full sing-box adds ~25 MB per ABI. Xray has no AnyTLS outbound. A gomobile
libcore AAR cannot ship beside the Psiphon AAR — duplicate `libgojni.so` and
`go.Seq` classes collide. A ~3 MB sidecar executable, launched with
`ProcessBuilder` from `nativeLibraryDir` exactly like `libtor.so` and
`libxray.so`, inherits the proven process model at a fraction of the size.

## Build (see .github/workflows/anytls-binary.yml)

    GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-android26-clang \
      go build -trimpath -buildmode=pie -ldflags "..." -o libanytls.so ./cmd/anytls-client

Renames to `lib*.so` because Android only grants the execute bit to files the
APK packager recognises as native libraries. Never dlopen'd.

## Usage

    anytls-client -l 127.0.0.1:1080 -c /path/to/config.json

Config: `{ "listen": "127.0.0.1:1080", "server": "host:port", "password": "...",
"sni": "...", "insecure": false, "min_idle_session": 5 }`

Server addresses support the `anytls://password@host:port/?sni=...&insecure=1`
URI format as well.

## License

Upstream anytls-go carries **no LICENSE file** (checked 2026-09-13; the repo
returns no license via the GitHub API). Its dependency sing is GPLv3.
Vendored here for internal MSN-GUARD builds under the same understanding as
the other reference code the app already vendors (badvpn, lwIP); resolve
before any public release that ships `libanytls.so` — either get an
upstream licence decision or drop the feature from public builds.
