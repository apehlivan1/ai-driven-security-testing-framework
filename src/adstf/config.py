from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adstf.contracts import TargetConfig


def load_target_config(path: Path) -> TargetConfig:
    data = json.loads(path.read_text(encoding="utf-8"))
    return target_config_from_mapping(data)


def target_config_from_mapping(data: dict[str, Any]) -> TargetConfig:
    required = ["name", "base_url", "allowed_hosts", "enabled_modules"]
    missing = [key for key in required if key not in data]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"target config is missing required field(s): {joined}")

    return TargetConfig(
        name=str(data["name"]),
        base_url=str(data["base_url"]),
        allowed_hosts=list(data["allowed_hosts"]),
        enabled_modules=list(data["enabled_modules"]),
        allowed_schemes=list(data.get("allowed_schemes", ["http", "https"])),
        allowed_ports=[int(port) for port in data.get("allowed_ports", [80, 443])],
        max_actions=int(data.get("max_actions", 50)),
        test_users=dict(data.get("test_users", {})),
        metadata=dict(data.get("metadata", {})),
    )
