# ethos

`ethos` is a cross-platform Python CLI that enforces principle-based safety gates and generates a Signed Integrity Graph (SIG) per agent run.

## Install

```bash
pip install -e .
```

## Commands

- `ethos init`
- `ethos run --agent <name> --input <file> --out <dir>`
- `ethos gate --tool <tool_name> --payload <json_file>`
- `ethos check --file <transcript.jsonl>`
- `ethos sign --in <sig_graph.json> --out <sig.sig>`
- `ethos verify --sig <sig.sig> --in <sig_graph.json> --pub <sig.pub>`

## SIG outputs

- `sig.graph.json`: DAG events with nodes and edges
- `sig.summary.json`: risk score, violations, tool call decisions

## v1 checks

- Overconfidence heuristic
- Sensitive data detector (email/phone/SSN)
- Manipulation language heuristic

## Examples

See `/examples` for:

- `ethos.yaml`
- `sample_transcript.jsonl`
- `demo_run_output/` (generated graph, summary, and signature artifacts)
