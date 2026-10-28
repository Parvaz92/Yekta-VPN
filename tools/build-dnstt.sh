#!/usr/bin/env bash
set -euo pipefail

# Build the standalone DNSTT managed transport for Android. This runs in CI only.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/tools/dnstt-native/dnstt"
OUT="$ROOT/app/src/main/jniLibs"
NDK="${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is required}"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"

rm -rf "$SRC"
git clone --depth 1 --branch master https://github.com/tladesignz/dnstt.git "$SRC"
test "$(git -C "$SRC" rev-parse HEAD)" = "f1b9b97a269f83bad41d2ceef291b4d2c161cd11" || {
  echo "Unexpected DNSTT source revision" >&2
  exit 1
}

cd "$ROOT/tools/dnstt-native"

go mod download

go mod tidy

build_one() {
  local abi="$1" goarch="$2" cc="$3" goarm="${4:-}"
  local dest="$OUT/$abi/libdnstt.so"
  mkdir -p "$(dirname "$dest")"
  echo "Building DNSTT for $abi"
  if [[ -n "$goarm" ]]; then
    env GOOS=android GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=1 CC="$TOOLCHAIN/$cc" \
      go build -trimpath -buildmode=pie \
      -ldflags "-s -w -extldflags '-Wl,-z,max-page-size=16384 -Wl,-z,relro -Wl,-z,now'" \
      -o "$dest" .
  else
    env GOOS=android GOARCH="$goarch" CGO_ENABLED=1 CC="$TOOLCHAIN/$cc" \
      go build -trimpath -buildmode=pie \
      -ldflags "-s -w -extldflags '-Wl,-z,max-page-size=16384 -Wl,-z,relro -Wl,-z,now'" \
      -o "$dest" .
  fi
  "$TOOLCHAIN/llvm-strip" --strip-unneeded "$dest" || true
  test -s "$dest"
  file "$dest"
}

build_one arm64-v8a arm64 aarch64-linux-android26-clang
build_one armeabi-v7a arm armv7a-linux-androideabi26-clang 7
build_one x86_64 amd64 x86_64-linux-android26-clang

rm -rf "$SRC"
sha256sum "$OUT"/*/libdnstt.so
