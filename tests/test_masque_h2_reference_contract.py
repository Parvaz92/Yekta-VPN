from pathlib import Path


ROOT = Path(__file__).parents[1]
CORE = ROOT / "core/aether/src/lib.rs"
CORE_TEXT = CORE.read_text(encoding="utf-8")


def test_h2_probe_uses_connect_sni():
    for start, end in (
        ("async fn select_peer", "async fn select_wg_peers"),
        ("async fn hunt_masque_peer", "fn masque_carrier"),
    ):
        block = CORE_TEXT.split(start, 1)[1].split(end, 1)[0]
        assert "sni: if masque_h2::enabled()" in block
        assert "consts::CONNECT_SNI.to_string()" in block


def test_h2_cached_verification_selects_connect_sni_only_for_h2():
    block = CORE_TEXT.split("async fn quick_verify_masque_peer", 1)[1].split("async fn want_quick_reconnect", 1)[0]
    assert "if masque_h2::enabled()" in block
    assert "consts::CONNECT_SNI.to_string()" in block
    assert "quic::masque_sni()" in block


def test_h2_live_session_uses_connect_sni():
    block = CORE_TEXT.split("let tunnel_task = if h2", 1)[1].split("} else {", 1)[0]
    assert "sni: consts::CONNECT_SNI.to_string()" in block
    assert "sni: quic::masque_sni()?" not in block


def test_reference_api_ech_is_reused_by_masque_session():
    assert 'variable: "AETHER_ECH"' in (ROOT / "core/aether/src/tls.rs").read_text(encoding="utf-8")
    assert 'out["AETHER_ECH"] = echValue' in (ROOT / "app/src/main/java/com/msnguard/vpn/CoreConfig.kt").read_text(encoding="utf-8")


def test_masque_h2_always_fragments_client_hello():
    config = (ROOT / "app/src/main/java/com/msnguard/vpn/CoreConfig.kt").read_text(encoding="utf-8")
    marker = '        // Mixed-case SNI only inside fragment branch (FCAE parity).\n'
    block = config.split(marker, 1)[1].split('        // ECH:', 1)[0]
    assert 'if (isMasqueForEnv) {' in block
    assert 'out["AETHER_MASQUE_H2_FRAGMENT"] = "1"' in block


def test_masque_does_not_prepare_api_or_session_ech():
    config = (ROOT / "app/src/main/java/com/msnguard/vpn/CoreConfig.kt").read_text(encoding="utf-8")
    block = config.split("// ECH:", 1)[1].split("// Zero Trust", 1)[0]
    assert "val isWarpForIdentity = !isMasqueForEnv" in block
    assert 'out["AETHER_API_ECH"]' not in block
    assert 'echLower.isEmpty() && isMasqueForEnv' in block
    assert 'echValue = "auto"' in block
    assert 'out["AETHER_ECH"] = echValue' in block


def test_core_reuses_api_ech_for_h2_session():
    block = CORE_TEXT.split("async fn resolve_ech", 1)[1].split("fn masque_reconnect_delay", 1)[0]
    assert "account::api_ech_in_use()" in block
    assert "offering the ECHConfigList the WARP API took" in block
