"""Support-log contract: readable endpoints and an app-only core label."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REDACTOR = (ROOT / "app/src/main/java/com/msnguard/vpn/LogRedactor.kt").read_text()
SERVICE = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()

assert 'if (port.isEmpty()) ip else "$ip:$port"' in REDACTOR
assert 'raw\n        }' in REDACTOR
assert 'text.replace("Aether v2.3.0", "Aether v2.4.0")' in SERVICE
assert 'bundled native binary remains unchanged' in SERVICE
print("PASS endpoint literals remain readable and only the support-log label says Aether v2.4.0")
