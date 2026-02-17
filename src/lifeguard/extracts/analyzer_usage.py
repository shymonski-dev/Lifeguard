"""Budget tracking utilities for tool usage."""

from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Optional

_LOCK = Lock()
_SESSION: ContextVar[str] = ContextVar("lifeguard_budget_session", default="default")

DEFAULT_MAX_CALLS = 50
DEFAULT_MAX_TOKENS = 500_000
_MAX_WARNINGS = 50


@dataclass
class BudgetStatus:
    calls_used: int = 0
    calls_limit: int = DEFAULT_MAX_CALLS
    tokens_estimated: int = 0
    tokens_limit: int = DEFAULT_MAX_TOKENS
    gate_tripped: bool = False
    trip_reason: Optional[str] = None
    warnings: list[str] = field(default_factory=list)

    @property
    def calls_remaining(self) -> int:
        return max(0, self.calls_limit - self.calls_used)

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.tokens_limit - self.tokens_estimated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls_used": self.calls_used,
            "calls_limit": self.calls_limit,
            "calls_remaining": self.calls_remaining,
            "tokens_estimated": self.tokens_estimated,
            "tokens_limit": self.tokens_limit,
            "tokens_remaining": self.tokens_remaining,
            "gate_tripped": self.gate_tripped,
            "trip_reason": self.trip_reason,
            "warnings": list(self.warnings),
        }


_BUDGETS: dict[str, BudgetStatus] = {"default": BudgetStatus()}


def set_budget_session(session_id: str) -> object:
    return _SESSION.set(session_id)


def get_budget_status(session_id: Optional[str] = None) -> BudgetStatus:
    sid = session_id or _SESSION.get()
    with _LOCK:
        status = _BUDGETS.get(sid)
        if status is None:
            status = BudgetStatus(
                calls_limit=int(os.getenv("LIFEGUARD_MAX_CALLS", DEFAULT_MAX_CALLS)),
                tokens_limit=int(os.getenv("LIFEGUARD_MAX_TOKENS", DEFAULT_MAX_TOKENS)),
            )
            _BUDGETS[sid] = status
        return status


def check_budget_gate(
    estimated_tokens: int = 0, session_id: Optional[str] = None
) -> tuple[bool, Optional[str]]:
    status = get_budget_status(session_id)
    with _LOCK:
        if status.gate_tripped:
            return False, status.trip_reason

        if status.calls_used >= status.calls_limit:
            status.gate_tripped = True
            status.trip_reason = f"Call limit exceeded: {status.calls_used}/{status.calls_limit}"
            return False, status.trip_reason

        if status.tokens_estimated + int(estimated_tokens) > status.tokens_limit:
            status.gate_tripped = True
            status.trip_reason = (
                "Token limit would be exceeded: "
                f"{status.tokens_estimated + int(estimated_tokens)}/{status.tokens_limit}"
            )
            return False, status.trip_reason

        calls_pct = (
            (status.calls_used / status.calls_limit) * 100 if status.calls_limit > 0 else 0.0
        )
        if calls_pct >= 80.0 and len(status.warnings) < _MAX_WARNINGS:
            status.warnings.append(
                f"Calls at {calls_pct:.0f}% of budget ({status.calls_used}/{status.calls_limit})"
            )
        return True, None


def record_budget_usage(
    calls: int = 1, tokens: int = 0, session_id: Optional[str] = None
) -> None:
    status = get_budget_status(session_id)
    with _LOCK:
        status.calls_used += int(calls)
        status.tokens_estimated += int(tokens)

