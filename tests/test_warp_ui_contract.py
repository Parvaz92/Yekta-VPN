"""Guard the first-connect MASQUE budget and live Identity Vault state."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
UI = (APP / "MainActivity.kt").read_text()
SERVICE = (APP / "MsnGuardVpnService.kt").read_text()
CORE = (ROOT / "core/aether/src/lib.rs").read_text()


class WarpUiContract(unittest.TestCase):
    def test_masque_first_connect_budget_is_80_seconds(self):
        budget = UI.split("private fun autoScanBudgetMs(protocol: Protocol)", 1)[1].split("\n    }", 1)[0]
        self.assertIn("Protocol.MASQUE -> if (CoreConfig.mimArmed(this)) 75_000L else 80_000L", budget)
        self.assertIn("autoScanBudgetMs(AUTO_SCAN_LADDER[rung])", UI)

    def test_vault_reflects_identity_created_on_home_screen(self):
        self.assertIn("IdentityRelayClient.provision(this@MsnGuardVpnService, relayProtocol)", SERVICE)
        self.assertIn("fun hasVaultIdentity(p: String): Boolean = IdentityProvisioner.hasIdentity", UI)
        self.assertIn("refreshWarpIdentityCards = ::refreshVaultCards", UI)
        self.assertIn("if (warpSettingPage != null) refreshWarpIdentityCards?.invoke()", UI)
        self.assertIn("refreshWarpIdentityCards = null", UI)
        self.assertRegex(UI, r"\(card\.getChildAt\(0\) as\? TextView\)\?\.text\s*=\s*\n\s*if \(isOk\)")

    def test_cache_is_after_warp_enable_in_core(self):
        start = CORE.index("async fn load_or_provision_masque(")
        run = CORE.index("async fn run_masque(")
        self.assertLess(start, run)
        self.assertIn("account::enable_warp(&identity.device_id, &identity.access_token)", CORE[start:run])
        self.assertIn("verifying cached gateway", CORE[run:])


if __name__ == "__main__":
    unittest.main()
