"""DNSTT must remain an isolated Tor PT and use Orbot's Iran bridges."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOR = (ROOT / "app/src/main/java/com/msnguard/vpn/TorManager.kt").read_text()
BRIDGES = (ROOT / "app/src/main/java/com/msnguard/vpn/DnsttBridges.kt").read_text()
WORKFLOW = (ROOT / ".github/workflows/build.yml").read_text()
SCRIPT = (ROOT / "tools/build-dnstt.sh").read_text()

assert 'DNSTT("dnstt", "DNS Tunnel"' in TOR
assert 'TorMode.DNSTT -> listOf("dnstt")' in TOR
assert 'TorMode.DNSTT -> DnsttBridges.lines(context, File(context.filesDir, "tor_data"))' in TOR
assert 'binaryName = if (transports == listOf("dnstt")) "libdnstt.so"' in TOR
assert 'DnsttResolverScanner.prepare(context, dataDir)' in BRIDGES
assert 'udp=$resolver:53' in BRIDGES
SCANNER = (ROOT / "app/src/main/java/com/msnguard/vpn/DnsttResolverScanner.kt").read_text()
RESOLVERS = ROOT / "app/src/main/assets/dnstt-resolvers-ir.txt"
assert 'dnstt-working-resolvers-ir.txt' in SCANNER
assert 'DNSTT_FRESH_SCAN_PREF' in SCANNER
assert 'scanning 7629 resolvers in order' in SCANNER
assert 'private const val WORKERS = 1' in SCANNER
assert 'readIps(cache).firstOrNull()' in SCANNER
assert '        stopDnsttScan()' not in TOR
assert 'cache.delete()' in SCANNER
assert 'first.await(FIRST_RESULT_TIMEOUT_MS' in SCANNER
assert 'executor.shutdown()' in SCANNER
assert 'process.inputStream.bufferedReader().useLines' in SCANNER
assert 'process.errorStream.bufferedReader()' in SCANNER
assert 'fields[2] == "socks5"' in SCANNER
assert 'done.await(METHOD_TIMEOUT_MS, TimeUnit.MILLISECONDS)' in SCANNER
assert 'FIRST_RESULT_TIMEOUT_MS = 15_000L' in SCANNER
assert 'PROBE_TIMEOUT_MS = 30_000' in SCANNER
assert 'starting Tor with DoH fallback' in SCANNER
assert 'doh=https://dns.google/dns-query' in BRIDGES
assert 'process start failed' in SCANNER
assert 'catch (_: java.io.IOException)' in SCANNER
assert 'scanner log reader reach the process default exception handler' in SCANNER
BUILD = (ROOT / "app/build.gradle.kts").read_text()
assert 'versionCode = 430' in BUILD and 'versionName = "3.1.33"' in BUILD
assert RESOLVERS.exists() and sum(1 for line in RESOLVERS.read_text().splitlines() if line.strip()) == 7629
assert 'tools/build-dnstt.sh' in WORKFLOW
assert "go-version: '1.25'" in WORKFLOW
assert 'f1b9b97a269f83bad41d2ceef291b4d2c161cd11' in SCRIPT
assert 'libdnstt.so' in SCRIPT
print("PASS DNSTT is an isolated managed PT with Orbot Iran bridge lines")
