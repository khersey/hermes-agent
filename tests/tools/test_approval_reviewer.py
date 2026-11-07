"""Generic reviewer selection keeps builtin behavior and original authority floors."""
from copy import deepcopy
import pytest

from hermes_cli.config import atomic_config_write, load_config_readonly
from tools import approval


def configure(home, **settings):
    config = deepcopy(load_config_readonly())
    config.setdefault('approvals', {}).update(settings)
    atomic_config_write(home/'config.yaml', config)


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr(approval, '_presence', lambda cb=None: (cb, True, False, False))
    monkeypatch.setattr(approval, '_yolo_active', lambda: False)
    monkeypatch.setattr(approval, 'is_approved', lambda *args: False)
    monkeypatch.setattr(approval, '_command_matches_permanent_allowlist', lambda *args: False)
    configure(tmp_path, mode='smart')
    return tmp_path


def test_default_reviewer_is_registered_configuration(gate):
    config = load_config_readonly()
    assert config['approvals']['reviewer'] == 'builtin'
    assert 0 < config['approvals']['reviewer_timeout'] <= 30


def test_builtin_default_calls_only_original_judge(gate, monkeypatch):
    calls = []
    monkeypatch.setattr(approval, '_smart_verdict', lambda *a: calls.append(a) or 'approve')
    result = approval.check_all_command_guards('python -c "print(1)"', 'local')
    assert result['smart_approved'] is True
    assert len(calls) == 1


@pytest.mark.parametrize('selection', ['unavailable', None, False, 'BAD NAME'])
def test_unknown_or_malformed_selection_is_human_not_builtin(gate, monkeypatch, selection):
    configure(gate, reviewer=selection)
    monkeypatch.setattr(approval, '_smart_verdict', lambda *a: pytest.fail('builtin fallback forbidden'))
    calls = []
    monkeypatch.setattr(approval, 'prompt_dangerous_approval', lambda *a, **kw: calls.append(kw) or 'deny')
    assert approval.check_all_command_guards('python -c "print(1)"', 'local')['approved'] is False
    assert len(calls) == 1


@pytest.mark.parametrize('mode', ['manual', 'off'])
def test_custom_reviewer_cannot_run_outside_smart(gate, monkeypatch, mode):
    configure(gate, reviewer='missing', mode=mode)
    import tools.approval_reviewer as reviewer
    monkeypatch.setattr(reviewer, 'review_shell', lambda *a: pytest.fail('not smart'))
    monkeypatch.setattr(approval, 'prompt_dangerous_approval', lambda *a, **kw: 'deny')
    result = approval.check_all_command_guards('python -c "print(1)"', 'local')
    assert result['approved'] is (mode == 'off')


def test_custom_selection_never_overrides_hardline_or_user_deny(gate, monkeypatch):
    configure(gate, reviewer='missing', deny=['*REPLACEMENT_USER_DENY*'])
    monkeypatch.setattr(approval, '_smart_verdict', lambda *a: pytest.fail('builtin called'))
    monkeypatch.setattr(approval, 'prompt_dangerous_approval', lambda *a, **kw: pytest.fail('floor bypass'))
    for command in ('rm -rf /', 'python -c "REPLACEMENT_USER_DENY"'):
        assert approval.check_all_command_guards(command, 'local')['approved'] is False


def test_config_read_failure_does_not_silently_select_builtin(gate, monkeypatch):
    from hermes_cli import config
    from tools.approval_reviewer import reviewer_selection
    def unreadable():
        raise OSError('synthetic config unavailable')
    monkeypatch.setattr(config, 'load_config_readonly', unreadable)
    assert reviewer_selection() != 'builtin'


def test_execution_fence_refusal_never_retries_or_logs_proposal(gate, monkeypatch, caplog):
    from types import SimpleNamespace
    import json
    from tools import terminal_tool
    from tools.approval_reviewer import ReviewExecutionError
    def refuse(*a, **kw):
        raise ReviewExecutionError('review binding changed; command not run')
    monkeypatch.setattr(terminal_tool, '_resolve_command_cwd', lambda **kw: str(gate))
    monkeypatch.setattr(terminal_tool, '_yield_kwargs', lambda *a, **kw: {})
    monkeypatch.setattr(terminal_tool.time, 'sleep', lambda *a: pytest.fail('review refusal retried'))
    plan = SimpleNamespace(env_type='local', effective_task_id='task', effective_timeout=5, cwd=str(gate), host_cwd=None)
    result = terminal_tool._run_foreground('SECRET_PROPOSAL', SimpleNamespace(execute=refuse), plan,
        task_id='task', session_id='session', session_key='route', workdir=None,
        approval_note=None, clear_interrupt=False, metered=False)
    assert json.loads(result)['status'] == 'blocked'
    assert 'SECRET_PROPOSAL' not in caplog.text


def test_scope_cleanup_failure_is_sanitized_and_context_is_restored():
    from types import SimpleNamespace
    from tools.approval_reviewer import shell_review_call, _current
    def broken_release(action):
        raise RuntimeError('SECRET_RELEASE_CONTEXT')
    with shell_review_call():
        _current.get().attempt = (SimpleNamespace(release=broken_release), None)
    assert _current.get() is None


def test_selected_reviewer_never_judges_whole_code_or_protected_tool_consent(gate, monkeypatch):
    configure(gate, reviewer='unavailable')
    monkeypatch.setattr(approval, '_presence', lambda cb=None: (cb, False, True, False))
    monkeypatch.setattr(approval, '_is_local_viewer_turn', lambda: False)
    monkeypatch.setattr(approval, '_gateway_notify_cb', lambda *a: None)
    monkeypatch.setattr(approval, '_smart_verdict', lambda *a: pytest.fail('builtin fallback'))
    import tools.approval_reviewer as reviewer
    monkeypatch.setattr(reviewer, 'review_shell', lambda *a: pytest.fail('not a supported shell request'))
    assert approval.check_execute_code_guard('print(1)', 'local')['approved'] is False
    assert approval.request_tool_approval('write_file', 'protected consent')['approved'] is False


@pytest.mark.parametrize('policy,allowed', [('deny', False), ('approve', True)])
def test_unattended_cron_policy_stays_authoritative(gate, monkeypatch, policy, allowed):
    configure(gate, reviewer='unavailable', cron_mode=policy)
    monkeypatch.setattr(approval, '_presence', lambda cb=None: (cb, False, False, False))
    monkeypatch.setattr(approval, '_unattended_contexts', lambda: [approval._CRON_CTX])
    import tools.approval_reviewer as reviewer
    monkeypatch.setattr(reviewer, 'review_shell', lambda *a: pytest.fail('cron policy bypass'))
    assert approval.check_all_command_guards('python -c "print(1)"', 'local')['approved'] is allowed
