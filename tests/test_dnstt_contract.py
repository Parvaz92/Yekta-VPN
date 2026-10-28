"""DNSTT must remain an isolated Tor PT and use Orbot's Iran bridges."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOR = (ROOT / "app/src/main/java/com/msnguard/vpn/TorManager.kt").read_text()
BRIDGES = (ROOT / "app/src/main/java/com/msnguard/vpn/DnsttBridges.kt").read_text()
WORKFLOW = (ROOT / ".github/workflows/build.yml").read_text()
SCRIPT = (ROOT / "tools/build-dnstt.sh").read_text()

assert 'DNSTT("dnstt", "DNS Tunnel"' in TOR
assert 'TorMode.DNSTT -> listOf("dnstt")' in TOR
assert 'TorMode.DNSTT -> DnsttBridges.lines()' in TOR
assert 'binaryName = if (transports == listOf("dnstt")) "libdnstt.so"' in TOR
assert 'dnstt 192.0.2.4:1 A998F319ADB60EE344540EC4B21524CC484F96BE' in BRIDGES
assert 'dnstt 192.0.2.4:2 80EEFA4F4875ED2B7B5A86DF2D7588AD32E29F15' in BRIDGES
assert 'tools/build-dnstt.sh' in WORKFLOW
assert "go-version: '1.25'" in WORKFLOW
assert 'f1b9b97a269f83bad41d2ceef291b4d2c161cd11' in SCRIPT
assert 'libdnstt.so' in SCRIPT
print("PASS DNSTT is an isolated managed PT with Orbot Iran bridge lines")
