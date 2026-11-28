import json
import sys

import pytest

from mcp_canary import analyze, server


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(server, "LOG_PATH", path)
    return path


def _events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def restore_settings():
    s = server.mcp.settings
    saved = (s.host, s.port, s.transport_security)
    yield
    s.host, s.port, s.transport_security = saved


def test_read_file_flags_sensitive_traversal(log_path):
    out = server.read_file("../../.ssh/id_rsa")
    (ev,) = _events(log_path)
    assert ev["tool"] == "read_file"
    assert ev["severity"] == "high"
    assert set(ev["flags"]) == {"sensitive_path", "path_traversal"}
    assert ev["canary"] in out


def test_canary_report_flags_poison_obedience(log_path):
    server.canary_report("CANARY-FILE-READ")
    server.canary_report("something-else")
    first, second = _events(log_path)
    assert first["flags"] == ["poison_obedience"] and first["severity"] == "high"
    assert second["flags"] == [] and second["severity"] == "info"


def test_long_args_are_truncated(log_path):
    server.run_command("curl " + "A" * 500)
    (ev,) = _events(log_path)
    assert len(ev["args"]["command"]) == 200
    assert "high_risk_command" in ev["flags"]


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_main_http_applies_host_and_port(monkeypatch, restore_settings, transport):
    calls = []
    monkeypatch.setattr(server.mcp, "run", lambda **kw: calls.append(kw))
    monkeypatch.setattr(
        sys, "argv", ["mcp-canary", "--transport", transport, "--host", "0.0.0.0", "--port", "9123"]
    )
    server.main()
    assert calls == [{"transport": transport}]
    assert server.mcp.settings.host == "0.0.0.0"
    assert server.mcp.settings.port == 9123
    # Non-loopback bind: the localhost-only Host allow-list must not apply.
    assert server.mcp.settings.transport_security is None


def test_loopback_bind_keeps_host_allow_list(restore_settings):
    before = server.mcp.settings.transport_security
    server.configure_http("127.0.0.1", 8001)
    assert server.mcp.settings.port == 8001
    assert server.mcp.settings.transport_security is before


def test_main_stdio(monkeypatch):
    calls = []
    monkeypatch.setattr(server.mcp, "run", lambda **kw: calls.append(kw))
    monkeypatch.setattr(sys, "argv", ["mcp-canary"])
    server.main()
    assert calls == [{"transport": "stdio"}]


def test_analyze_groups_sessions_and_skips_bad_lines(tmp_path, monkeypatch, capsys):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({"session": "s1", "tool": "get_secrets", "severity": "critical", "flags": ["credential_probe"]})
        + "\nnot json\n\n"
        + json.dumps({"session": "s1", "tool": "list_directory", "severity": "medium", "flags": []})
        + "\n"
    )
    monkeypatch.setattr(sys, "argv", ["mcp-canary-analyze", str(path)])
    analyze.main()
    out = capsys.readouterr().out
    assert "Session s1 — 2 events — max severity: critical" in out


def test_analyze_skips_json_lines_that_are_not_event_objects(tmp_path, monkeypatch, capsys):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '["not", "an", "event"]\n"just a string"\n42\nnull\n'
        + json.dumps({"session": ["odd"], "tool": "get_secrets", "severity": "critical", "flags": []})
        + "\n"
    )
    monkeypatch.setattr(sys, "argv", ["mcp-canary-analyze", str(path)])
    analyze.main()
    out = capsys.readouterr().out
    assert "1 events — max severity: critical" in out
