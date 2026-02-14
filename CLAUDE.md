# CLAUDE.md

## Project Overview

**Ethos** is a principle-based safety gate CLI for AI agents. It enforces safety principles (evidence-based claims, privacy preservation, non-manipulation) by scoring agent transcripts and tool payloads against heuristic checks, then producing allow/deny decisions and a cryptographically signed Signed Integrity Graph (SIG).

- **Version:** 0.1.0
- **Language:** Python 3.10+
- **CLI framework:** Typer
- **Entry point:** `ethos.cli:app` (installed as the `ethos` command)

## Repository Structure

```
.
├── ethos/                  # Main package
│   ├── __init__.py         # Version string (0.1.0)
│   ├── cli.py              # Typer CLI commands (init, check, gate, run, sign, verify)
│   ├── checks.py           # Safety check implementations (overconfidence, sensitive_data, manipulation)
│   ├── config.py           # YAML config loading and EthosConfig dataclass
│   └── sig.py              # Ed25519 keypair generation, signing, and verification
├── tests/
│   ├── test_checks.py      # Unit tests for the three safety checks
│   └── test_sig.py         # Unit tests for sign/verify roundtrip and tamper detection
├── examples/
│   ├── ethos.yaml          # Example configuration
│   ├── sample_transcript.jsonl
│   ├── tool_payload.json
│   └── demo_run_output/    # Example SIG graph, summary, and signature files
├── ethos.yaml              # Root project configuration (used at runtime)
├── pyproject.toml          # Build config, dependencies, pytest settings
├── README.md
└── .gitignore
```

## Setup and Installation

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

## Common Commands

### Run Tests

```bash
pytest
```

Test paths are configured in `pyproject.toml` under `[tool.pytest.ini_options]` to use the `tests/` directory. There are 5 tests total across two files.

### Run the CLI

```bash
ethos init                    # Generate ethos.yaml, sig.key, sig.pub
ethos check --file <file.jsonl>
ethos gate --tool <name> --payload <file.json>
ethos run --agent <name> --input <file.jsonl> --out <dir>
ethos sign --in <graph.json> --out <sig.sig>
ethos verify --sig <sig.sig> --in <graph.json> --pub <sig.pub>
```

## Architecture and Key Concepts

### Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `ethos/cli.py` | CLI commands, transcript parsing, orchestration of checks and signing |
| `ethos/checks.py` | Three heuristic safety checks returning `CheckResult(name, score, explanation)` |
| `ethos/config.py` | Loading `ethos.yaml` into `EthosConfig` dataclass, generating default config |
| `ethos/sig.py` | Ed25519 keypair generation, canonical JSON serialization, signing, verification |

### Safety Checks (v1)

Each check returns a `CheckResult` dataclass with a score in `[0, 1]` (0 = safe, 1 = maximum risk):

1. **`overconfidence_check`** - Detects certainty phrases ("definitely", "guaranteed", etc.) without evidence markers (URLs, citations). Score range: 0.7-1.0, reduced by 0.4 if evidence is present.
2. **`sensitive_data_check`** - Regex patterns for email, US phone numbers, and SSNs. Score range: 0.35-1.0 based on hit count.
3. **`manipulation_check`** - Detects coercive phrases ("you must obey", "or else", etc.). Score range: 0.4-1.0 based on hit count.

### Risk Scoring

- **Overall risk** = average of all individual check scores
- **Decision:** `deny` if overall >= `overall_deny` threshold (default 0.8), otherwise `allow`
- Thresholds are configurable in `ethos.yaml`

### Signed Integrity Graph (SIG)

The `run` command produces a DAG where each transcript event becomes a node linked sequentially by "follows" edges. Each node stores a SHA256 content hash. The graph can be signed with Ed25519 (`sign` command) and verified later (`verify` command) using canonical JSON serialization for deterministic hashing.

## Code Conventions

### Naming

- Private helpers prefixed with `_` (e.g., `_utc_ts()`, `_run_checks()`, `_clip()`)
- Check functions follow pattern: `<name>_check()` (e.g., `overconfidence_check()`)
- CLI commands are plain functions matching their subcommand name (`init`, `check`, `gate`, `run`, `sign`, `verify`)

### Patterns

- **Type hints** throughout, using `from __future__ import annotations` for forward references
- **Dataclasses** for structured data (`CheckResult`, `EthosConfig`)
- **Stateless pure functions** for checks and crypto operations
- **Score clipping** via `_clip()` to enforce `[0, 1]` range
- **Canonical JSON** (sorted keys, compact separators) for deterministic signing
- **`pathlib.Path`** used everywhere for file operations

### File Conventions

- Generated key/signature files (`sig.key`, `sig.pub`, `sig.sig`) are gitignored
- Configuration is YAML (`ethos.yaml`)
- Transcripts are JSONL (one JSON object per line)
- Tool payloads are single JSON files

## Dependencies

| Package | Purpose |
|---------|---------|
| `typer>=0.12.0` | CLI framework |
| `pyyaml>=6.0.1` | YAML configuration parsing |
| `cryptography>=42.0.0` | Ed25519 key generation, signing, and verification |
| `pytest>=8.0.0` (dev) | Test runner |

## Configuration

The `ethos.yaml` at the project root controls runtime behavior:

- **`principles`** - List of named safety principles with descriptions
- **`require_uncertainty`** - Boolean; when `false`, disables the overconfidence check
- **`risk_thresholds`** - Float thresholds for deny/escalate decisions and per-check limits
- **`escalation`** - Rules for when to require human approval
- **`tool_policies`** - Per-tool allow/deny rules with score-based conditions

## Things to Know When Making Changes

- There is no linter or formatter configured. Follow existing style (type hints, dataclasses, private helpers with `_` prefix).
- No CI/CD pipeline exists. Run `pytest` locally before committing.
- The `_clip()` function in `checks.py` must be used when computing check scores to keep them in `[0, 1]`.
- Signature verification depends on canonical JSON (`sort_keys=True, separators=(",", ":")`) -- any change to serialization will break existing signatures.
- The `ethos init` command is idempotent: it only creates files that don't already exist.
