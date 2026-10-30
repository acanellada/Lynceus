import json
import subprocess
from pathlib import Path

import pytest

from lynceus_sec.validator import runner
from lynceus_sec.validator.runner import (
    HARNESS_PATH,
    RunnerError,
    build_docker_command,
    parse_harness_output,
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


def test_home_env_set_to_tmp():
    _, cmd = build_docker_command(CASE_DIR)

    idx = cmd.index("-e")
    assert cmd[idx + 1] == "HOME=/tmp"


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
