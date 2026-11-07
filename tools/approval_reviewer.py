"""Explicit smart-review provider ABI and scoped local-shell execution fence.

Providers are trusted in-process policy code, not human approval transports.
No conversation/history is accepted here: original human ingress is unavailable.
"""
from abc import ABC, abstractmethod
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from functools import wraps
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time

_HOST_INSTANCE = secrets.token_hex(32)
logger = logging.getLogger(__name__)
_current: ContextVar = ContextVar('shell_review_call', default=None)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     allow_nan=False).encode('ascii')).hexdigest()


@dataclass(frozen=True)
class ShellAction:
    request_id: str
    host_id: str
    profile_id: str
    session_id: str
    turn_id: str
    call_id: str
    command: str
    cwd: str
    shell: str
    environment_digest: str
    execution_digest: str
    policy_digest: str
    untrusted_context: tuple[str, ...]

    def binding(self):
        return fingerprint(asdict(self))


@dataclass(frozen=True)
class ReviewResult:
    decision: str
    action_digest: str
    receipt: dict


class ApprovalReviewer(ABC):
    """Synchronous, deadline-cooperative policy; no default or implicit selection.

    Implementations MUST bound their I/O by deadline and never execute proposals.
    Core rejects late responses; it creates no unbounded callback thread pool.
    """
    name: str

    @abstractmethod
    def review(self, action: ShellAction, *, deadline: float) -> ReviewResult:
        ...

    @abstractmethod
    def consume(self, result: ReviewResult, action: ShellAction) -> bool:
        ...

    @abstractmethod
    def execution_valid(self, action: ShellAction) -> bool:
        """Recheck lifecycle/settings immediately before the one approved spawn."""
        ...

    @abstractmethod
    def release(self, action: ShellAction) -> None:
        """Discard pending/consumed state when the host call scope ends."""
        ...


class ReviewExecutionError(RuntimeError):
    """Fixed, command-free execution-fence refusal."""


class _Scope:
    def __init__(self):
        from tools.interrupt import acting_for_tid
        # Deadline workers copy this scope, not their caller's thread identity.
        # Keep both the physical tool owner and any incoming logical owner.
        self.interrupt_tids = (threading.get_ident(), acting_for_tid.get())
        self.request_id = secrets.token_hex(16)
        self.active = True
        self.builder = None
        self.permit = None
        self.required = False
        self.environment = None
        self.attempt = None
        self.lock = threading.Lock()


@contextmanager
def shell_review_call():
    scope = _Scope()
    token = _current.set(scope)
    try:
        yield
    finally:
        with scope.lock:
            scope.active = False
            scope.permit = None
            scope.builder = None
            attempt = scope.attempt
            scope.attempt = None
        if attempt:
            provider, action = attempt
            try:
                provider.release(action)
            except Exception:  # health: allow BLE001 -- scope already revoked; suppress private plugin cleanup exception text
                logger.warning('Approval reviewer cleanup failed; call scope already revoked')
        _current.reset(token)


def reviewed_shell_call(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with shell_review_call():
            return function(*args, **kwargs)
    return wrapped


def reviewer_selection():
    from hermes_cli.config import load_config_readonly
    from hermes_cli.config_backend import ConfigBackendUnavailable
    try:
        name = load_config_readonly().get('approvals', {}).get('reviewer', 'builtin')
    except (OSError, ValueError, TypeError, AttributeError, ConfigBackendUnavailable):
        return 'invalid-selection'
    if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}', name):
        return 'invalid-selection'
    return name


def _policy():
    from hermes_cli.config import load_config_readonly
    from tools.approval_context import _get_approval_mode, get_current_session_key
    return fingerprint({'config': load_config_readonly(), 'mode': _get_approval_mode(),
                        'session_route': get_current_session_key(default='')})


def _identity(path):
    st = Path(path).stat()
    return [st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size]


def _local_action(scope, command, env, cwd):
    from agent.redact import redact_sensitive_text
    from hermes_constants import hermes_home_key
    from tools import approval_context as context
    from tools.environments.local import _find_bash, _make_run_env
    from tools.terminal_tool_macos_open import _transform_macos_open_command
    from tools.terminal_tool_sudo import _rewrite_compound_background
    ids = (context._approval_session_id.get(), context._approval_turn_id.get(), context._approval_tool_call_id.get())
    if any(not re.fullmatch('[A-Za-z0-9._:-]{1,128}', value) for value in ids):
        raise ValueError('missing_review_scope')
    if not env._snapshot_ready or re.search(r'\bsudo\b', command):
        raise ValueError('unsupported_shell_state')
    if _rewrite_compound_background(command) != command or _transform_macos_open_command(command) != command:
        raise ValueError('unsupported_rewrite')
    if str(Path(cwd).resolve()) != cwd or not Path(cwd).is_dir():
        raise ValueError('unsupported_cwd')
    shell, run_env = _find_bash(), _make_run_env(env.env)
    if not Path(shell).is_absolute() or Path(shell).name not in ('bash', 'sh') or any(
            run_env.get(k) for k in ('BASH_ENV', 'ENV')) or any(k.startswith('BASH_FUNC_') for k in run_env):
        raise ValueError('unsupported_shell_environment')
    with open(env._snapshot_path, 'rb') as stream:
        snapshot = stream.read(32769)
    if len(snapshot) > 32768 or len(command.encode('utf-8')) > 16384:
        raise ValueError('review_input_limit')
    text = snapshot.decode('utf-8')
    if any(redact_sensitive_text(value, force=True) != value for value in (command, cwd, text)):
        raise ValueError('material_redaction')
    wrapped = env._wrap_command(command, cwd)
    execution = fingerprint({'args': [shell, '-c', wrapped], 'snapshot': text,
                             'snapshot_identity': _identity(env._snapshot_path),
                             'cwd_identity': _identity(cwd)[:2], 'spawn_cwd': env.cwd,
                             'spawn_cwd_identity': _identity(env.cwd)[:2],
                             'shell_identity': _identity(shell), 'environment_object': id(env)})
    return ShellAction(scope.request_id, _HOST_INSTANCE, fingerprint(hermes_home_key()), *ids,
                       command, cwd, shell, fingerprint(run_env), execution, _policy(),
                       ('Untrusted mutable shell snapshot (not human consent):\n'+text,))


def bind_local_shell(*, command, env, cwd, backend, background):
    """Only the real built-in foreground POSIX environment has a spawn fence."""
    from tools.environments.local import LocalEnvironment
    scope = _current.get()
    if scope is not None and backend == 'local' and os.name == 'posix' and type(env) is LocalEnvironment and not background:
        scope.environment = env
        scope.builder = lambda: _local_action(scope, command, env, cwd() if callable(cwd) else cwd)


def _deadline():
    from tools.approval_context import _get_approval_config
    value = _get_approval_config().get('reviewer_timeout', 10)
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or not 0 < value <= 30:
        raise ValueError('invalid_reviewer_timeout')
    return time.monotonic()+value


def review_shell(selected, command):
    """Return allow/deny/abstain; a custom selection NEVER invokes the builtin."""
    from tools.approval_reviewer_registry import get_provider
    from tools.interrupt import is_interrupted
    scope = _current.get()
    provider = get_provider(selected)
    if scope is None or scope.builder is None or provider is None:
        return 'abstain'
    try:
        deadline = _deadline()
        action = scope.builder()
        if action.command != command:
            return 'abstain'
        scope.attempt = (provider, action)
        result = provider.review(action, deadline=deadline)
        if (type(result) is not ReviewResult or result.action_digest != action.binding() or
                result.decision not in ('allow', 'deny', 'abstain')):
            return 'abstain'
        with scope.lock:
            if (not scope.active or is_interrupted() or time.monotonic() >= deadline or
                    reviewer_selection() != selected or get_provider(selected) is not provider or
                    scope.builder() != action):
                return 'abstain'
            if provider.consume(result, action) is not True:
                return 'abstain'
            if result.decision == 'allow':
                if is_interrupted() or time.monotonic() >= deadline or scope.builder() != action:
                    return 'abstain'
                scope.required = True
                scope.permit = (action, provider, selected, deadline, False)
        return result.decision
    except Exception:  # health: allow BLE001 -- abstain at plugin policy boundary without logging sensitive exception text
        return 'abstain'


def consume_local_shell(env, args, run_env, cwd, stdin_data):
    """Last check immediately before Popen; drift/retry/cancel cannot reuse allow."""
    from tools.approval_reviewer_registry import get_provider
    from tools.interrupt import is_interrupted, is_thread_interrupted
    scope = _current.get()
    if scope is None or not scope.required:
        return
    with scope.lock:
        if scope.permit is None:
            raise ReviewExecutionError('review call ended; command not run')
        action, provider, selected, deadline, used = scope.permit
        scope.permit = (action, provider, selected, deadline, True)
        try:
            valid = (not used and env is scope.environment and
                     scope.builder() == action and args == [action.shell, '-c', env._wrap_command(action.command, action.cwd)] and
                     fingerprint(run_env) == action.environment_digest and cwd == env.cwd and stdin_data is None and
                     reviewer_selection() == selected and get_provider(selected) is provider)
            # Record/config reconstruction may block. Recheck revocation and expiry
            # afterward, including time spent in the provider's lifecycle check.
            if valid:
                valid = (provider.execution_valid(action) is True and scope.active and
                         not is_interrupted() and not any(is_thread_interrupted(tid) for tid in scope.interrupt_tids) and
                         time.monotonic() < deadline)
        except Exception:  # health: allow BLE001 -- execution fence refuses plugin failures without leaking sensitive inputs
            valid = False
        if not valid:
            raise ReviewExecutionError('review execution binding expired or changed; command not run')
