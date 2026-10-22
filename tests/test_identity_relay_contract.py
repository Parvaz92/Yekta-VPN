"""Static relay/core contract checks; run with python3.10 -m unittest discover -s tests."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
RELAY = (APP / "IdentityRelayClient.kt").read_text()
PROVISIONER = (APP / "IdentityProvisioner.kt").read_text()
SERVICE = (APP / "MsnGuardVpnService.kt").read_text()
UI = (APP / "MainActivity.kt").read_text()
CORE_ACCOUNT = (ROOT / "core/aether/src/account.rs").read_text()
CORE_CONFIG = (ROOT / "core/aether/src/config.rs").read_text()
CORE_LIB = (ROOT / "core/aether/src/lib.rs").read_text()


class RelayContract(unittest.TestCase):
    def test_core_fields(self):
        fields = re.findall(r"pub (\w+):", CORE_CONFIG.split("impl From<&Identity>")[0])
        emitted = re.findall(r'appendLine\("(\w+) = ', PROVISIONER.split("fun relayToml")[1].split("fun installRelayedFiles")[0])
        self.assertEqual(set(fields), set(emitted))
        self.assertIn('optJSONObject("addresses")', PROVISIONER)
        self.assertIn('optJSONArray("peers")', PROVISIONER)
        self.assertIn('optString("public_key")', PROVISIONER)

    def test_core_path_and_credentials(self):
        self.assertIn('let secondary_path = derive_sibling_path(&primary_path, "secondary")', CORE_LIB)
        self.assertIn('let secondary_path = derive_sibling_path(&primary_path, "secondary")', CORE_LIB.split('Protocol::MasqueInMasque =>')[1])
        for filename in ("aether.toml", "aether-masque.toml", "aether-secondary.toml", "aether-masque-secondary.toml"):
            self.assertIn(filename, RELAY)
        self.assertIn('"secp256r1"', RELAY)
        self.assertIn('"masque"', RELAY)
        self.assertIn('KEY_TYPE_MASQUE: &str = "secp256r1"', (ROOT / "core/aether/src/consts.rs").read_text())
        for key in ('"key"', '"tos"', '"key_type"', '"tunnel_type"'):
            self.assertIn('put(' + key, RELAY)
        self.assertIn('JSONObject().put("warp_enabled", true)', RELAY)
        self.assertIn('if (!enabled.optBoolean("warp_enabled", false))', RELAY)
        self.assertIn('request(endpoint, "PATCH", ENROLL_PATH_PREFIX + deviceId, update, token)', RELAY)
        self.assertIn('wg_private_key', CORE_CONFIG)
        self.assertIn('cert_pem', CORE_CONFIG)

    def test_worker_ladder_auth_and_no_fallback(self):
        self.assertIn('listOf(RELAY_A, RELAY_B)', RELAY)
        self.assertIn('X-MSN-Timestamp', RELAY)
        self.assertIn('X-MSN-Nonce', RELAY)
        self.assertIn('X-MSN-Signature', RELAY)
        self.assertIn('"$method\\n$path\\n$timestamp\\n$nonce\\n$body"', RELAY)
        self.assertNotIn('ShardManager', RELAY)
        self.assertIn('IdentityRelayClient.provision(this@MsnGuardVpnService', SERVICE)
        self.assertIn('IdentityRelayClient.provision(this@MsnGuardVpnService, protocol)', SERVICE)
        self.assertIn('var vaultMethod: String = "relay"', UI)
        self.assertIn('MSN_IDENTITY_RELAY_HMAC: ${{ secrets.MSN_IDENTITY_RELAY_HMAC }}',
                      (ROOT / '.github/workflows/build.yml').read_text())

    def test_identity_validator_accepts_numbered_toml_keys(self):
        validator = PROVISIONER.split('fun validIdentityFile')[1].split('fun hasIdentity')[0]
        self.assertIn('org.tomlj.Toml.parse(file.toPath())', validator)
        self.assertIn('fields.hasErrors()', validator)
        for key in ('device_id', 'access_token', 'ipv4', 'wg_private_key', 'wg_peer_public_key',
                    'cert_pem', 'key_pem', 'cert_issued_at'):
            self.assertIn('"' + key + '"', validator)
        self.assertIn('fields.getLong("cert_issued_at")', validator)
        self.assertIn('implementation("org.tomlj:tomlj:2.2.0")',
                      (ROOT / 'app/build.gradle.kts').read_text())

    def test_no_private_data_in_logging(self):
        for forbidden in ('Log.i(TAG, response', 'ConnectionLog.record(response', 'Log.w(TAG, body', 'ConnectionLog.record(body'):
            self.assertNotIn(forbidden, RELAY)
        self.assertIn('if (cancelled()) return Outcome(false, "cancelled")', RELAY)
        self.assertIn('validIdentityFile(temp, target.name.contains("masque"))', PROVISIONER)
        self.assertIn('installed.forEach { it.delete() }', PROVISIONER)
        self.assertIn('backups.forEach { (target, backup) -> backup.renameTo(target) }', PROVISIONER)


if __name__ == '__main__':
    unittest.main()
