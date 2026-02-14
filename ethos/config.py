from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class EthosConfig:
    principles: list[dict[str, str]]
    require_uncertainty: bool
    risk_thresholds: dict[str, float]
    escalation: list[dict[str, Any]]
    tool_policies: list[dict[str, Any]]


def default_config() -> dict[str, Any]:
    return {
        "principles": [
            {
                "name": "Evidence-based claims",
                "description": "Avoid certainty when evidence or citations are absent.",
            },
            {
                "name": "Privacy preservation",
                "description": "Detect and prevent sensitive data leakage.",
            },
            {
                "name": "Non-manipulation",
                "description": "Disallow coercive or manipulative language.",
            },
        ],
        "require_uncertainty": True,
        "risk_thresholds": {
            "overall_deny": 0.8,
            "overall_escalate": 0.6,
            "overconfidence": 0.5,
            "sensitive_data": 0.5,
            "manipulation": 0.5,
        },
        "escalation": [
            {
                "name": "high_overall_risk",
                "when": "overall_risk_score >= overall_escalate",
                "action": "require_human_approval",
            }
        ],
        "tool_policies": [
            {"tool_name": "shell", "allow": True, "conditions": "overall_risk_score < overall_deny"},
            {"tool_name": "web_search", "allow": True, "conditions": "overall_risk_score < overall_deny"},
            {"tool_name": "delete_files", "allow": False, "conditions": "always"},
        ],
    }


def write_default_config(path: Path) -> None:
    path.write_text(yaml.safe_dump(default_config(), sort_keys=False), encoding="utf-8")


def load_config(path: Path) -> EthosConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return EthosConfig(
        principles=data.get("principles", []),
        require_uncertainty=data.get("require_uncertainty", True),
        risk_thresholds=data.get("risk_thresholds", {}),
        escalation=data.get("escalation", []),
        tool_policies=data.get("tool_policies", []),
    )
