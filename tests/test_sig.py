import json
from pathlib import Path

from ethos.sig import generate_keypair, sign_graph, verify_graph_signature


def test_sign_and_verify_roundtrip(tmp_path: Path) -> None:
    graph = {"nodes": [{"id": "n1", "type": "event", "ts": "2026-01-01T00:00:00Z", "content_hash": "abc", "metadata": {}}], "edges": []}
    graph_path = tmp_path / "sig.graph.json"
    graph_path.write_text(json.dumps(graph), encoding="utf-8")

    private_key = tmp_path / "sig.key"
    public_key = tmp_path / "sig.pub"
    signature = tmp_path / "sig.sig"

    generate_keypair(private_key, public_key)
    sign_graph(graph_path, private_key, signature)
    ok, _ = verify_graph_signature(signature, graph_path, public_key)

    assert ok


def test_verify_fails_when_graph_changes(tmp_path: Path) -> None:
    graph_path = tmp_path / "sig.graph.json"
    graph_path.write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")

    private_key = tmp_path / "sig.key"
    public_key = tmp_path / "sig.pub"
    signature = tmp_path / "sig.sig"

    generate_keypair(private_key, public_key)
    sign_graph(graph_path, private_key, signature)

    graph_path.write_text(json.dumps({"nodes": [{"id": "n2"}], "edges": []}), encoding="utf-8")
    ok, _ = verify_graph_signature(signature, graph_path, public_key)

    assert not ok
