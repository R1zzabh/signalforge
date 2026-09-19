from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

@dataclass
class ProviderResult:
    provider: str
    status: str
    queried_at: str
    latency_ms: int
    data: dict[str, Any]
    error: str | None = None
    mode: str = "LIVE"

class Provider:
    name = "provider"
    def __init__(self, *, demo: bool = False, timeout: float = 5.0):
        self.demo = demo; self.timeout = timeout
    def normalize(self, payload: Any) -> dict[str, Any]: return payload if isinstance(payload, dict) else {}
    def health_check(self) -> ProviderResult:
        return ProviderResult(self.name, "DEMO_FIXTURE" if self.demo else "UNAVAILABLE", datetime.now(timezone.utc).isoformat(), 0, {}, None if self.demo else "credentials or endpoint not configured", "DEMO" if self.demo else "LIVE")
    def lookup(self, indicator: str) -> ProviderResult:
        return ProviderResult(self.name, "DEMO_FIXTURE" if self.demo else "UNAVAILABLE", datetime.now(timezone.utc).isoformat(), 0, {}, None if self.demo else "provider adapter not configured", "DEMO" if self.demo else "LIVE")
