from pathlib import Path


ROOT = Path(__file__).parents[1]
CORE = ROOT / "core/aether/src/lib.rs"
CORE_TEXT = CORE.read_text(encoding="utf-8")


def test_masque_h2_uses_configured_sni_for_probe_cache_and_session():
    for start, end in (
        ("async fn select_peer", "async fn select_wg_peers"),
        ("async fn hunt_masque_peer", "fn masque_carrier"),
        ("async fn quick_verify_masque_peer", "async fn want_quick_reconnect"),
    ):
        block = CORE_TEXT.split(start, 1)[1].split(end, 1)[0]
        assert "quic::masque_sni()" in block
    block = CORE_TEXT.split("let tunnel_task = if h2", 1)[1].split("} else {", 1)[0]
    assert "sni: quic::masque_sni()?" in block


def test_existing_masque_identity_does_not_reenable_warp():
    block = CORE_TEXT.split("async fn load_or_provision_masque", 1)[1].split(
        "async fn load_or_enrol_masque", 1
    )[0]
    assert "load_or_enrol_masque(config_path).await" in block
    assert "account::enable_warp" not in block


def test_new_masque_identity_enables_warp_before_save():
    block = CORE_TEXT.split("log::info!(\"[+] no masque identity found", 1)[1].split(
        "/// The identities `--register`", 1
    )[0]
    assert "account::enable_warp(&identity.device_id, &identity.access_token).await?" in block
    assert block.index("enable_warp") < block.index("config::save")


def test_h2_applies_fingerprint_to_context_and_connection_options():
    block = (ROOT / "core/aether/src/masque_h2.rs").read_text(encoding="utf-8")
    assert "let fingerprint = tls::Fingerprint::configured();" in block
    assert "fingerprint.apply(&mut builder, H2_ALPN)?;" in block


def test_regular_ipv4_scan_uses_reference_gateway_set_before_ranges():
    prober = (ROOT / "core/aether/src/prober.rs").read_text(encoding="utf-8")
    assert "pub const MASQUE_GATEWAYS_V4" in prober
    assert "let regular_v4 = MASQUE_GATEWAYS_V4.iter()" in prober
    assert "if zero_trust_mode()" in prober
    assert "let cidr_hosts: Vec<Vec<Ipv4Addr>> = if zero_trust_mode()" in prober


def test_masque_h2_keeps_api_ech_disabled_when_no_key_is_available():
    tls = (ROOT / "core/aether/src/tls.rs").read_text(encoding="utf-8")
    config = (ROOT / "app/src/main/java/com/msnguard/vpn/CoreConfig.kt").read_text(encoding="utf-8")
    assert 'variable: "AETHER_API_ECH"' in tls
    assert 'if (socksProxyForCore.isBlank() && !isMasqueForEnv)' in config
    assert 'out["AETHER_API_ECH"] = echValue' in config


def test_masque_h2_keeps_fragmentation_opt_in():
    config = (ROOT / "app/src/main/java/com/msnguard/vpn/CoreConfig.kt").read_text(encoding="utf-8")
    marker = '        // H2 fragmentation is opt-in, matching the working profile\'s default.\n'
    block = config.split(marker, 1)[1].split('        // ECH:', 1)[0]
    assert 'if (isMasqueForEnv) {' in block
    assert 'out["AETHER_MASQUE_H2_FRAGMENT"] = "0"' in block


def test_masque_does_not_prepare_api_or_session_ech():
    config = (ROOT / "app/src/main/java/com/msnguard/vpn/CoreConfig.kt").read_text(encoding="utf-8")
    block = config.split("// ECH:", 1)[1].split("// Zero Trust", 1)[0]
    assert "val isWarpForIdentity = !isMasqueForEnv" in block
    assert 'echLower.isEmpty() && isMasqueForEnv' not in block
    assert 'out["AETHER_API_ECH"]' in block
    assert 'out["AETHER_ECH"] = echValue' in block
    assert 'if (isMasqueForEnv) {' in block
    assert 'out.remove("AETHER_API_ECH")' in block


def test_masque_startup_budget_covers_api_and_scan():
    service = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text(encoding="utf-8")
    activity = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text(encoding="utf-8")
    assert "MtuConfig.Method.MASQUE -> 300_000L" in service
    assert "Protocol.MASQUE -> if (CoreConfig.mimArmed(this)) 300_000L else 300_000L" in activity
