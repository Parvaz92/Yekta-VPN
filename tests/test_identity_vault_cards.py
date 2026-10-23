"""Exercise real TOML parsing for each Identity Vault card without Android builds."""
import base64
import pathlib
import subprocess
import tempfile
import textwrap
import unittest
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
SOURCE = (APP / "IdentityProvisioner.kt").read_text()
UI = (APP / "MainActivity.kt").read_text()
CORE = (ROOT / "core/aether/src/lib.rs").read_text()
URL = "https://repo.maven.apache.org/maven2/org/tomlj/tomlj/2.2.0/tomlj-2.2.0.jar"


def identity(masque=False, malformed=False):
    key = base64.b64encode(bytes(range(32))).decode()
    cert = '-----BEGIN CERTIFICATE-----\\nABC\\n-----END CERTIFICATE-----'
    private = '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----'
    return (f'device_id = "device"\naccess_token = "token"\nipv4 = "172.16.0.2"\n'
            f'ipv6 = "2606:4700:110::2"\nwg_private_key = "{key}"\n'
            f'wg_peer_public_key = "{key}"\n'
            f'cert_pem = "{cert if masque else ""}"\n'
            f'key_pem = "{private if masque else ""}"\n'
            f'cert_issued_at = {1_700_000_000 if masque and not malformed else 0}\n')


class IdentityVaultContract(unittest.TestCase):
    def test_four_cards_use_the_same_files_as_core(self):
        paths = SOURCE.split('fun hasIdentity', 1)[1].split('private fun siblingFile', 1)[0]
        self.assertIn('"masque" -> validIdentityFile(masque, true)', paths)
        self.assertIn('validIdentityFile(masque, true) && validIdentityFile(siblingFile(masque, "secondary"), true)', paths)
        self.assertIn('validIdentityFile(base, false) && validIdentityFile(siblingFile(base, "secondary"), false)', paths)
        self.assertIn('else -> validIdentityFile(base, false)', paths)
        for suffix in ('"masque"', '"secondary"'):
            self.assertIn('derive_sibling_path', CORE)
            self.assertIn(suffix, CORE)
        self.assertIn('"masque" to "MASQUE", "mim" to "MiM", "wireguard" to "WireGuard", "gool" to "WoW"', UI)
        self.assertIn('IdentityProvisioner.hasIdentity(this, vaultProtocolSelected(p))', UI)
        self.assertIn('if (warpSettingPage != null) refreshWarpIdentityCards?.invoke()', UI)

    def test_parser_handles_core_and_relay_files(self):
        # A real TOML parser accepts Rust's serialized escaped PEM strings and
        # rejects incomplete identities; this reproduces the four card inputs.
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            jar = work / 'tomlj.jar'
            urllib.request.urlretrieve(URL, jar)
            java = work / 'IdentityCheck.java'
            java.write_text(textwrap.dedent('''
                import java.nio.file.*;
                import java.util.*;
                import org.tomlj.*;
                public class IdentityCheck {
                    static boolean valid(Path p, boolean masque) throws Exception {
                        if (!Files.exists(p)) return false;
                        TomlParseResult t = Toml.parse(p);
                        if (t.hasErrors()) return false;
                        String id = t.getString("device_id"), token = t.getString("access_token");
                        String ipv4 = t.getString("ipv4");
                        if (id == null || id.isEmpty() || token == null || token.isEmpty() || ipv4 == null || ipv4.isEmpty()) return false;
                        for (String key : new String[] {"wg_private_key", "wg_peer_public_key"}) {
                            String value = t.getString(key);
                            if (value == null || Base64.getDecoder().decode(value).length != 32) return false;
                        }
                        if (!masque) return true;
                        String cert = t.getString("cert_pem"), privateKey = t.getString("key_pem");
                        Long issued = t.getLong("cert_issued_at");
                        return cert != null && cert.contains("BEGIN CERTIFICATE") && privateKey != null &&
                            privateKey.contains("BEGIN PRIVATE KEY") && issued != null && issued > 0;
                    }
                    public static void main(String[] args) throws Exception {
                        Path base = Paths.get(args[0]);
                        Path masque = base.resolveSibling("aether-masque.toml");
                        System.out.print(valid(masque, true) + "," +
                            (valid(masque, true) && valid(base.resolveSibling("aether-masque-secondary.toml"), true)) + "," +
                            (valid(base, false) && valid(base.resolveSibling("aether-secondary.toml"), false)) + "," +
                            valid(base, false));
                    }
                }
            '''))
            subprocess.run(['javac', '-cp', str(jar), str(java)], check=True)
            files = [work / 'aether.toml', work / 'aether-masque.toml',
                     work / 'aether-secondary.toml', work / 'aether-masque-secondary.toml']
            def state():
                output = subprocess.check_output(['java', '-cp', str(work) + ':' + str(jar),
                                                  'IdentityCheck', str(files[0])], text=True)
                return output.strip()
            self.assertEqual(state(), 'false,false,false,false')
            files[1].write_text(identity(masque=True))
            self.assertEqual(state(), 'true,false,false,false')
            files[0].write_text(identity())
            self.assertEqual(state(), 'true,false,false,true')
            files[2].write_text(identity())
            self.assertEqual(state(), 'true,false,true,true')
            files[3].write_text(identity(masque=True))
            self.assertEqual(state(), 'true,true,true,true')
            # TOML multiline strings are also valid for PEM data.
            files[1].write_text(identity(masque=True).replace(
                'cert_pem = "-----BEGIN CERTIFICATE-----\\\\nABC\\\\n-----END CERTIFICATE-----"',
                'cert_pem = """\\n-----BEGIN CERTIFICATE-----\\nABC\\n-----END CERTIFICATE-----\\n"""'))
            self.assertEqual(state(), 'true,true,true,true')
            files[1].write_text(identity(masque=True, malformed=True))
            self.assertEqual(state(), 'false,false,true,true')


if __name__ == '__main__':
    unittest.main()
