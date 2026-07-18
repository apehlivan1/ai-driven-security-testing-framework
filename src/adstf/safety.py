from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from adstf.contracts import ActionRequest, SafetyClass, TargetConfig


@dataclass(frozen=True)
class SafetyDecision:
    approved: bool
    reasons: list[str]


class SafetyBoundary:
    def __init__(self, target: TargetConfig) -> None:
        self._target = target

    def evaluate(self, action: ActionRequest) -> SafetyDecision:
        return self.evaluate_url(self._action_url(action), action.module_id, action.safety_class)

    def evaluate_url(
        self,
        url: str | None,
        module_id: str | None = None,
        safety_class: SafetyClass = SafetyClass.LOW,
    ) -> SafetyDecision:
        reasons: list[str] = []

        if safety_class == SafetyClass.HIGH:
            reasons.append("high-risk actions are not allowed in the scaffold")

        if url:
            parsed = urlparse(url)
            if parsed.scheme not in self._target.allowed_schemes:
                reasons.append(f"scheme '{parsed.scheme}' is not in the target allowlist")
            if parsed.hostname not in self._target.allowed_hosts:
                reasons.append(f"host '{parsed.hostname}' is not in the target allowlist")
            port = parsed.port or self._default_port(parsed.scheme)
            if port not in self._target.allowed_ports:
                reasons.append(f"port '{port}' is not in the target allowlist")

        if module_id and module_id not in self._target.enabled_modules:
            reasons.append(f"module '{module_id}' is not enabled for this run")

        return SafetyDecision(approved=not reasons, reasons=reasons)

    def resolve_url(self, base_url: str, maybe_relative: str) -> str:
        return urljoin(base_url, maybe_relative)

    def _action_url(self, action: ActionRequest) -> str | None:
        url = action.parameters.get("url")
        if isinstance(url, str):
            return url
        if action.target_ref.startswith(("http://", "https://")):
            return action.target_ref
        return None

    def _default_port(self, scheme: str) -> int:
        if scheme == "https":
            return 443
        return 80
