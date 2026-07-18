from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from adstf.config import load_target_config
from adstf.contracts import ActionRequest, ActionType, EvidenceType, SafetyClass
from adstf.execution import HttpExecutor
from adstf.lifecycle import new_id
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.storage import RunArtifactStore


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "dvwa-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


def run_dvwa_smoke(config_path: Path, output_root: Path) -> Path:
    target = load_target_config(config_path)
    run_id = f"dvwa-smoke-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)

    safety = SafetyBoundary(target)
    executor = HttpExecutor(safety)

    in_scope = ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dvwa_smoke",
        module_id=None,
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=f"{target.base_url}/login.php",
        scope_context={"target": target.name},
        parameters={
            "method": "GET",
            "url": f"{target.base_url}/login.php",
            "max_redirects": 3,
        },
        preconditions=["dvwa_running_locally"],
        safety_class=SafetyClass.LOW,
        rationale="Verify that an in-scope DVWA page can be requested and recorded.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )
    out_of_scope = ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dvwa_smoke",
        module_id=None,
        action_type=ActionType.REPLAY_REQUEST,
        target_ref="http://example.com/",
        scope_context={"target": target.name},
        parameters={"method": "GET", "url": "http://example.com/"},
        preconditions=[],
        safety_class=SafetyClass.LOW,
        rationale="Verify that an out-of-scope request is blocked and recorded.",
        expected_evidence=[EvidenceType.BLOCKED_ACTION],
    )

    in_scope_status = None
    for action in (in_scope, out_of_scope):
        store.save_action_request(action)
        result, evidence_records = executor.execute(action)
        for evidence in evidence_records:
            store.save_evidence(evidence)
        store.save_action_result(result)
        if action is in_scope:
            in_scope_status = result.status.value

    store.save_report(render_placeholder_report(target, []))
    if in_scope_status != "executed":
        raise RuntimeError(
            "DVWA smoke request did not execute successfully. "
            f"Artifacts were written to {store.run_dir}. "
            "Confirm DVWA is running locally at the configured base_url."
        )
    return store.run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the live local DVWA HTTP smoke test.")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to the DVWA target configuration.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Directory where smoke-test artifacts are written.",
    )
    args = parser.parse_args()
    try:
        run_dir = run_dvwa_smoke(args.config, args.output_root)
    except RuntimeError as exc:
        print(f"DVWA smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"DVWA smoke artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
