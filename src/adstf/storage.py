from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adstf.contracts import (
    ActionRequest,
    ActionResult,
    EvidenceRecord,
    FindingRecord,
    TargetConfig,
    VerifierResult,
)
from adstf.serialization import to_json_value


@dataclass(frozen=True)
class RunArtifactStore:
    root: Path
    run_id: str

    @property
    def run_dir(self) -> Path:
        return self.root / self.run_id

    def initialize(self, target: TargetConfig) -> None:
        for name in ("actions", "results", "evidence", "findings", "verification"):
            (self.run_dir / name).mkdir(parents=True, exist_ok=True)
        self._write_json(self.run_dir / "target.json", target)

    def save_action_request(self, action: ActionRequest) -> Path:
        return self._write_json(self.run_dir / "actions" / f"{action.action_id}.json", action)

    def save_action_result(self, result: ActionResult) -> Path:
        return self._write_json(self.run_dir / "results" / f"{result.action_id}.json", result)

    def save_evidence(self, evidence: EvidenceRecord) -> Path:
        return self._write_json(self.run_dir / "evidence" / f"{evidence.evidence_id}.json", evidence)

    def save_finding(self, finding: FindingRecord) -> Path:
        return self._write_json(self.run_dir / "findings" / f"{finding.finding_id}.json", finding)

    def save_verifier_result(self, result: VerifierResult) -> Path:
        return self._write_json(
            self.run_dir / "verification" / f"{result.verification_result_id}.json",
            result,
        )

    def save_report(self, report_markdown: str) -> Path:
        path = self.run_dir / "report.md"
        path.write_text(report_markdown, encoding="utf-8")
        return path

    def _write_json(self, path: Path, value: Any) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(to_json_value(value), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path
