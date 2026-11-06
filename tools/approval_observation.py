"""Optional, host-owned shell hints for non-authorizing approval observers.

These are pre-execution hints, not cwd/shell/environment or consent attestations.
No observer return value is consulted by an approval gate.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class ShellApprovalContext:
    backend: str
    base_cwd: str
    requested_workdir: str | None

    def observer_payload(self) -> dict:
        from agent.redact import redact_sensitive_text
        return {
            "version": 1,
            "backend": self.backend[:128],
            "base_cwd": redact_sensitive_text(self.base_cwd[:4096], force=True),
            "requested_workdir": (redact_sensitive_text(self.requested_workdir[:4096], force=True)
                                  if self.requested_workdir is not None else None),
            "shell": None,
            "cwd_evidence": "pre_execution_hint_not_attestation",
        }


_current: ContextVar[ShellApprovalContext | None] = ContextVar("shell_approval_context", default=None)


def current_shell_context() -> ShellApprovalContext | None:
    return _current.get()


@contextmanager
def shell_approval_context(*, backend: str, cwd: str, requested_workdir: str | None):
    token = _current.set(ShellApprovalContext(backend, cwd, requested_workdir))
    try:
        yield
    finally:
        _current.reset(token)
