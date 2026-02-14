from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from ethos.checks import CheckResult, manipulation_check, overconfidence_check, sensitive_data_check
from ethos.config import load_config, write_default_config
from ethos.sig import generate_keypair, hash_content, sign_graph, verify_graph_signature

app = typer.Typer(help="Ethos CLI: principle-based safety gates with Signed Integrity Graph output.")


def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_transcript(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _run_checks(text: str, require_uncertainty: bool = True) -> list[CheckResult]:
    return [
        overconfidence_check(text, require_uncertainty=require_uncertainty),
        sensitive_data_check(text),
        manipulation_check(text),
    ]


def _build_summary(checks: list[CheckResult], tool_name: str | None = None, threshold: float = 0.8) -> dict[str, Any]:
    overall = sum(c.score for c in checks) / len(checks)
    violations = [
        {"name": c.name, "score": c.score, "explanation": c.explanation}
        for c in checks
        if c.score > 0.0
    ]

    decisions: list[dict[str, Any]] = []
    if tool_name:
        decisions.append(
            {
                "tool_name": tool_name,
                "decision": "deny" if overall >= threshold else "allow",
                "reason": f"overall_risk_score={overall:.2f} threshold={threshold:.2f}",
            }
        )

    return {
        "overall_risk_score": round(overall, 4),
        "violations": violations,
        "tool_decisions": decisions,
    }


@app.command()
def init() -> None:
    """Initialize ethos config and Ed25519 signing keys."""
    config_path = Path("ethos.yaml")
    private_key_path = Path("sig.key")
    public_key_path = Path("sig.pub")

    if not config_path.exists():
        write_default_config(config_path)
    if not private_key_path.exists() or not public_key_path.exists():
        generate_keypair(private_key_path, public_key_path)

    typer.echo("Initialized ethos.yaml, sig.key, and sig.pub")


@app.command()
def check(file: Path = typer.Option(..., "--file", exists=True, readable=True)) -> None:
    """Run v1 checks against a transcript JSONL file."""
    config = load_config(Path("ethos.yaml")) if Path("ethos.yaml").exists() else None
    require_uncertainty = True if config is None else config.require_uncertainty

    entries = _load_transcript(file)
    all_text = "\n".join(json.dumps(e, ensure_ascii=False) for e in entries)
    summary = _build_summary(_run_checks(all_text, require_uncertainty=require_uncertainty))
    typer.echo(json.dumps(summary, indent=2))


@app.command()
def gate(
    tool: str = typer.Option(..., "--tool"),
    payload: Path = typer.Option(..., "--payload", exists=True, readable=True),
) -> None:
    """Evaluate a tool payload against safety checks and return allow/deny."""
    config = load_config(Path("ethos.yaml")) if Path("ethos.yaml").exists() else None
    threshold = 0.8 if config is None else config.risk_thresholds.get("overall_deny", 0.8)

    payload_json = _read_json_file(payload)
    payload_text = json.dumps(payload_json, ensure_ascii=False)
    require_uncertainty = True if config is None else config.require_uncertainty
    checks = _run_checks(payload_text, require_uncertainty=require_uncertainty)
    summary = _build_summary(checks, tool_name=tool, threshold=threshold)
    typer.echo(json.dumps(summary, indent=2))


@app.command()
def run(
    agent: str = typer.Option(..., "--agent"),
    input: Path = typer.Option(..., "--input", exists=True, readable=True),
    out: Path = typer.Option(..., "--out"),
) -> None:
    """Run checks for an agent transcript and emit SIG graph + summary."""
    out.mkdir(parents=True, exist_ok=True)
    config = load_config(Path("ethos.yaml")) if Path("ethos.yaml").exists() else None
    threshold = 0.8 if config is None else config.risk_thresholds.get("overall_deny", 0.8)

    events = _load_transcript(input)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    previous_id: str | None = None
    for i, event in enumerate(events):
        eid = f"n{i+1}"
        serialized = json.dumps(event, sort_keys=True, ensure_ascii=False)
        node = {
            "id": eid,
            "type": event.get("type", "event"),
            "ts": event.get("ts", _utc_ts()),
            "content_hash": hash_content(serialized),
            "metadata": {
                "agent": agent,
                "role": event.get("role"),
                "tool_name": event.get("tool_name"),
            },
        }
        nodes.append(node)
        if previous_id:
            edges.append({"from": previous_id, "to": eid, "relation": "follows"})
        previous_id = eid

    full_text = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
    require_uncertainty = True if config is None else config.require_uncertainty
    checks = _run_checks(full_text, require_uncertainty=require_uncertainty)

    tool_decisions = []
    for event in events:
        if event.get("type") == "tool_call":
            tool_payload = json.dumps(event.get("payload", {}), ensure_ascii=False)
            tool_checks = _run_checks(tool_payload, require_uncertainty=require_uncertainty)
            tool_summary = _build_summary(tool_checks, tool_name=event.get("tool_name", "unknown"), threshold=threshold)
            tool_decisions.extend(tool_summary["tool_decisions"])

    summary = _build_summary(checks, threshold=threshold)
    summary["tool_decisions"] = tool_decisions

    graph = {"nodes": nodes, "edges": edges}

    (out / "sig.graph.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")
    (out / "sig.summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    typer.echo(f"Wrote {out / 'sig.graph.json'} and {out / 'sig.summary.json'}")


@app.command()
def sign(
    in_file: Path = typer.Option(..., "--in", exists=True, readable=True),
    out: Path = typer.Option(..., "--out"),
) -> None:
    """Sign canonical JSON of a SIG graph using sig.key."""
    private_key_path = Path("sig.key")
    if not private_key_path.exists():
        raise typer.BadParameter("sig.key not found. Run `ethos init` first.")

    sign_graph(in_file, private_key_path, out)
    typer.echo(f"Wrote signature to {out}")


@app.command()
def verify(
    sig: Path = typer.Option(..., "--sig", exists=True, readable=True),
    in_file: Path = typer.Option(..., "--in", exists=True, readable=True),
    pub: Path = typer.Option(..., "--pub", exists=True, readable=True),
) -> None:
    """Verify signature against canonical JSON graph with Ed25519 public key."""
    ok, message = verify_graph_signature(sig, in_file, pub)
    if ok:
        typer.echo(message)
        raise typer.Exit(code=0)
    typer.echo(message)
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
