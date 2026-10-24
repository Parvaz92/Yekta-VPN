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
        assert "if masque_h2::enabled()" in block
        assert "consts::CONNECT_SNI.to_string()" in block
        assert "quic::masque_sni()?" in block


def test_h2_cached_verification_selects_connect_sni_only_for_h2():
    block = CORE_TEXT.split("async fn quick_verify_masque_peer", 1)[1].split("async fn want_quick_reconnect", 1)[0]
    assert "if masque_h2::enabled()" in block
    assert "consts::CONNECT_SNI.to_string()" in block
    assert "quic::masque_sni()" in block


def test_h2_live_session_uses_connect_sni():
    block = CORE_TEXT.split("let tunnel_task = if h2", 1)[1].split("} else {", 1)[0]
    assert "sni: consts::CONNECT_SNI.to_string()" in block
    assert "sni: quic::masque_sni()?" not in block
