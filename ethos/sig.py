from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def generate_keypair(private_path: Path, public_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)


def sign_graph(graph_path: Path, private_key_path: Path, signature_path: Path) -> None:
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    payload = canonical_json_bytes(graph)
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    signature = private_key.sign(payload)

    signature_path.write_text(
        json.dumps(
            {
                "algorithm": "ed25519",
                "graph_sha256": hashlib.sha256(payload).hexdigest(),
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def verify_graph_signature(signature_path: Path, graph_path: Path, public_key_path: Path) -> tuple[bool, str]:
    sig_doc = json.loads(signature_path.read_text(encoding="utf-8"))
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    payload = canonical_json_bytes(graph)
    current_hash = hashlib.sha256(payload).hexdigest()

    if current_hash != sig_doc.get("graph_sha256"):
        return False, "Graph hash mismatch."

    signature = base64.b64decode(sig_doc["signature_b64"])
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    assert isinstance(public_key, Ed25519PublicKey)

    try:
        public_key.verify(signature, payload)
        return True, "Signature verified."
    except Exception:
        return False, "Signature verification failed."
