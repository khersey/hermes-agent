"""Host-owned shell context enriches observer hooks, never approval authority."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier


def test_shell_context_is_scoped_optional_and_restored(monkeypatch):
    from tools import approval_context
    from hermes_cli import lifecycle
    import importlib.util
    assert importlib.util.find_spec("tools.approval_observation") is not None
    import tools.approval_observation as observation

    assert callable(getattr(observation, "shell_approval_context", None))
    seen = []
    monkeypatch.setattr(lifecycle, "invoke_hook", lambda name, **kw: seen.append(kw))
    approval_context._fire_approval_hook("pre_approval_request", command="redacted")
    assert "shell_context" not in seen[-1]
    with observation.shell_approval_context(backend="local", cwd="/base", requested_workdir="/requested"):
        approval_context._fire_approval_hook("pre_approval_request", command="redacted")
    assert seen[-1]["shell_context"] == {
        "version": 1, "backend": "local", "base_cwd": "/base",
        "requested_workdir": "/requested", "shell": None,
        "cwd_evidence": "pre_execution_hint_not_attestation",
    }
    approval_context._fire_approval_hook("pre_approval_request", command="redacted")
    assert "shell_context" not in seen[-1]


def test_parallel_context_and_exception_cleanup(monkeypatch):
    from tools import approval_context
    from hermes_cli import lifecycle
    import importlib.util
    assert importlib.util.find_spec("tools.approval_observation") is not None
    import tools.approval_observation as observation

    barrier = Barrier(2)
    seen = []
    monkeypatch.setattr(lifecycle, "invoke_hook", lambda name, **kw: seen.append(kw))

    def run(name):
        try:
            with observation.shell_approval_context(backend=name, cwd="/" + name, requested_workdir=None):
                barrier.wait(timeout=5)
                approval_context._fire_approval_hook("pre_approval_request", command=name)
                raise RuntimeError("cancel")
        except RuntimeError:
            pass
        assert observation.current_shell_context() is None

    with ThreadPoolExecutor(2) as pool:
        list(pool.map(run, ("local", "ssh")))
    assert {row["command"]: row["shell_context"]["backend"] for row in seen} == {"local": "local", "ssh": "ssh"}

def test_normal_terminal_path_binds_host_backend_and_cwd(monkeypatch, tmp_path):
    """Fixture environment, real terminal entry/approval path; no command execution."""
    from contextlib import nullcontext
    from types import SimpleNamespace
    from tools import terminal_tool
    from tools.approval_observation import current_shell_context
    seen = []
    plan = SimpleNamespace(env_type="local", cwd=str(tmp_path), effective_task_id="task", config={},
                           auto_background_command=None, effective_timeout=1)
    monkeypatch.setattr(terminal_tool, "_plan_execution", lambda *a, **kw: plan)
    monkeypatch.setattr(terminal_tool, "_acquire_env", lambda *a: object())
    monkeypatch.setattr(terminal_tool, "_call_in_flight", lambda *a: nullcontext())
    monkeypatch.setattr(terminal_tool, "_pre_exec_block", lambda *a, **kw: None)

    def denied(*a, **kw):
        seen.append(current_shell_context())
        return {"approved": False, "message": "fixture denial"}

    monkeypatch.setattr(terminal_tool, "_check_all_guards", denied)
    result = terminal_tool.terminal_tool("python -c 'print(1)'", workdir=str(tmp_path))
    assert "fixture denial" in result
    assert seen[0] is not None
    assert seen[0].backend == "local"
    assert seen[0].base_cwd == str(tmp_path)
    assert seen[0].requested_workdir == str(tmp_path)
    assert current_shell_context() is None
