import json
import subprocess
from pathlib import Path

import pytest

from lynceus_sec.validator import runner
from lynceus_sec.validator.runner import (
    HARNESS_PATH,
    RunnerError,
    build_docker_command,
    build_network_create_cmd,
    build_network_rm_cmd,
    build_receiver_command,
    check_network_isolation,
    parse_harness_output,
    read_receiver_log,
    run_harness,
)

CASE_DIR = Path("/some/case")


def test_includes_all_isolation_protections():
    _, cmd = build_docker_command(CASE_DIR)

    assert "--rm" in cmd
    assert "--network" in cmd and "none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_tmpfs_is_rw_noexec_nosuid_nodev_with_size_limit():
    _, cmd = build_docker_command(CASE_DIR)

    idx = cmd.index("--tmpfs")
    assert cmd[idx + 1] == "/tmp:rw,noexec,nosuid,nodev,size=16m"


def test_home_env_defaults_to_lynceus_root():
    _, cmd = build_docker_command(CASE_DIR)

    idx = cmd.index("-e")
    assert cmd[idx + 1] == "HOME=/tmp/lynceus-root"


def test_fs_root_overrides_home_env_and_keeps_rest_of_protections():
    _, cmd = build_docker_command(CASE_DIR, fs_root="/tmp/mi-limite")

    idx = cmd.index("-e")
    assert cmd[idx + 1] == "HOME=/tmp/mi-limite"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_entry_defaults_to_server_py():
    _, cmd = build_docker_command(CASE_DIR)

    assert "/case/server.py" in cmd


def test_entry_overrides_default_and_keeps_rest_of_protections():
    _, cmd = build_docker_command(CASE_DIR, entry="app/main.py")

    assert "/case/app/main.py" in cmd
    assert "/case/server.py" not in cmd
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_no_pythonpath_means_no_pythonpath_env_var():
    _, cmd = build_docker_command(CASE_DIR)

    assert not any(arg.startswith("PYTHONPATH=") for arg in cmd)


def test_pythonpath_sets_env_var_joined_under_case_and_keeps_rest_of_protections():
    _, cmd = build_docker_command(CASE_DIR, pythonpath=["lib", "vendor"])

    assert "PYTHONPATH=/case/lib:/case/vendor" in cmd
    idx = cmd.index("-e")
    assert cmd[idx + 1] == "HOME=/tmp/lynceus-root"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_no_server_python_means_no_server_python_flag():
    _, cmd = build_docker_command(CASE_DIR)

    assert "--server-python" not in cmd


def test_server_python_appends_flag_and_keeps_rest_of_protections():
    _, cmd = build_docker_command(CASE_DIR, server_python=runner.TARGET_PYTHON)

    idx = cmd.index("--server-python")
    assert cmd[idx + 1] == runner.TARGET_PYTHON
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_server_python_flag_comes_before_extra_harness_args():
    _, cmd = build_docker_command(CASE_DIR, server_python=runner.TARGET_PYTHON, extra_harness_args=["--mode", "validate"])

    assert cmd.index("--server-python") < cmd.index("--mode")


def test_run_harness_forwards_server_python_to_docker_command(monkeypatch):
    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_exists", lambda image: True)

    captured = {}

    def fake_build_docker_command(case_dir, **kwargs):
        captured.update(kwargs)
        return "lynceus-sandbox-abc", ["docker", "run", "--rm", "image"]

    monkeypatch.setattr(runner, "build_docker_command", fake_build_docker_command)
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps({"tools": []}), stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    run_harness(CASE_DIR, server_python=runner.TARGET_PYTHON)

    assert captured["server_python"] == runner.TARGET_PYTHON


def test_run_validate_forwards_server_python_to_docker_command(monkeypatch):
    from lynceus_sec.validator.runner import run_validate

    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_exists", lambda image: True)

    captured = {}

    def fake_build_docker_command(case_dir, **kwargs):
        captured.update(kwargs)
        return "lynceus-sandbox-abc", ["docker", "run", "--rm", "image"]

    monkeypatch.setattr(runner, "build_docker_command", fake_build_docker_command)
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps({"results": []}), stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    run_validate(CASE_DIR, [], server_python=runner.TARGET_PYTHON)

    assert captured["server_python"] == runner.TARGET_PYTHON


def test_container_name_changes_between_calls():
    name_a, _ = build_docker_command(CASE_DIR)
    name_b, _ = build_docker_command(CASE_DIR)

    assert name_a != name_b


def test_container_name_appears_in_command():
    name, cmd = build_docker_command(CASE_DIR)

    idx = cmd.index("--name")
    assert cmd[idx + 1] == name


def test_mounts_only_the_harness_file_not_the_package_dir():
    _, cmd = build_docker_command(CASE_DIR)

    mounts = [arg for i, arg in enumerate(cmd) if cmd[i - 1] == "-v"]
    assert f"{CASE_DIR}:/case:ro" in mounts
    assert f"{HARNESS_PATH}:/harness/harness.py:ro" in mounts
    assert len(mounts) == 2
    assert all(mount.rsplit(":", 2)[0] != str(HARNESS_PATH.parent) for mount in mounts)


def test_parse_harness_output_returns_tools():
    tools = parse_harness_output({"tools": [{"name": "ping", "input_schema": {}}]})

    assert tools == [{"name": "ping", "input_schema": {}}]


def test_parse_harness_output_rejects_error_payload():
    with pytest.raises(RunnerError, match="boom"):
        parse_harness_output({"error": "boom"})


def test_parse_harness_output_rejects_missing_tools_key():
    with pytest.raises(RunnerError, match="tools"):
        parse_harness_output({})


# --- _docker_responding: el daemon responde, no solo el binario está en el PATH ---


def test_docker_responding_true_when_docker_info_succeeds(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    assert runner._docker_responding() is True


def test_docker_responding_false_when_docker_info_fails(monkeypatch):
    completed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="Cannot connect to the Docker daemon",
    )
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    assert runner._docker_responding() is False


def test_docker_responding_false_on_timeout(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner._docker_responding() is False


def test_docker_responding_false_when_binary_is_missing(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner._docker_responding() is False


def test_run_harness_fails_clearly_without_docker(monkeypatch):
    monkeypatch.setattr(runner, "_docker_available", lambda: False)

    with pytest.raises(RunnerError, match="Docker"):
        run_harness(CASE_DIR)


def test_run_harness_fails_clearly_without_image(monkeypatch):
    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_exists", lambda image: False)

    with pytest.raises(RunnerError, match=runner.DEFAULT_IMAGE):
        run_harness(CASE_DIR)


def test_run_harness_parses_successful_output(monkeypatch):
    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_exists", lambda image: True)

    payload = {"tools": [{"name": "fetch", "input_schema": {}}]}
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    assert run_harness(CASE_DIR) == payload["tools"]


def test_run_harness_reports_harness_error_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_exists", lambda image: True)

    completed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout=json.dumps({"error": "boom"}), stderr=""
    )
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(RunnerError, match="boom"):
        run_harness(CASE_DIR)


def test_run_harness_kills_container_on_timeout(monkeypatch):
    monkeypatch.setattr(runner, "_docker_available", lambda: True)
    monkeypatch.setattr(runner, "_image_exists", lambda image: True)

    killed = []

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "kill"]:
            killed.append(cmd[2])
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    with pytest.raises(RunnerError, match="no terminó"):
        run_harness(CASE_DIR, timeout=1)

    assert len(killed) == 1


# --- SSRF: red interna, receptor, comprobación de aislamiento ---


def test_default_network_is_still_none():
    _, cmd = build_docker_command(CASE_DIR)

    idx = cmd.index("--network")
    assert cmd[idx + 1] == "none"


def test_network_param_overrides_default_and_keeps_rest_of_protections():
    _, cmd = build_docker_command(CASE_DIR, network="lynceus-net-abc123")

    idx = cmd.index("--network")
    assert cmd[idx + 1] == "lynceus-net-abc123"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_network_create_command_is_internal():
    cmd = build_network_create_cmd("lynceus-net-abc123")

    assert cmd == ["docker", "network", "create", "--internal", "lynceus-net-abc123"]


def test_network_rm_command_targets_the_right_network():
    cmd = build_network_rm_cmd("lynceus-net-abc123")

    assert cmd == ["docker", "network", "rm", "lynceus-net-abc123"]


def test_receiver_command_never_publishes_ports():
    name, cmd = build_receiver_command("lynceus-net-abc123")

    assert "-p" not in cmd
    assert "--publish" not in cmd
    idx = cmd.index("--network")
    assert cmd[idx + 1] == "lynceus-net-abc123"
    idx = cmd.index("--name")
    assert cmd[idx + 1] == name


def test_receiver_command_keeps_the_same_hardening_as_the_server():
    _, cmd = build_receiver_command("lynceus-net-abc123")

    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--user" in cmd and f"{runner.SANDBOX_UID}:{runner.SANDBOX_UID}" in cmd


def test_check_network_isolation_passes_when_output_is_exactly_isolation_ok(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ISOLATION_OK\n", stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    check_network_isolation("lynceus-net-abc123")  # no debe lanzar


def test_check_network_isolation_aborts_if_tcp_reachable(monkeypatch):
    completed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="ISOLATION_FAILED tcp_reachable=True dns_resolves=False\n", stderr="",
    )
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(RunnerError, match="aislada"):
        check_network_isolation("lynceus-net-abc123")


def test_check_network_isolation_aborts_if_external_name_resolves(monkeypatch):
    completed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="ISOLATION_FAILED tcp_reachable=False dns_resolves=True\n", stderr="",
    )
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(RunnerError, match="aislada"):
        check_network_isolation("lynceus-net-abc123")


def test_check_network_isolation_aborts_on_ambiguous_output(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="algo inesperado\n", stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(RunnerError, match="aislada"):
        check_network_isolation("lynceus-net-abc123")


def test_check_network_isolation_aborts_on_timeout(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    with pytest.raises(RunnerError, match="ambiguo"):
        check_network_isolation("lynceus-net-abc123")


def test_read_receiver_log_parses_json_lines_and_skips_garbage(monkeypatch):
    stdout = (
        '{"method": "GET", "path": "/tok-1", "host": "recv:8080"}\n'
        "esto no es json\n"
        '{"method": "GET", "path": "/tok-2", "host": "recv:8080"}\n'
    )
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed)

    entries = read_receiver_log("lynceus-receiver-abc123")

    assert [e["path"] for e in entries] == ["/tok-1", "/tok-2"]
