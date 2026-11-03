import hashlib
import subprocess
from pathlib import Path

import pytest

from lynceus_sec.validator import build


@pytest.fixture
def target(tmp_path):
    folder = tmp_path / "target"
    folder.mkdir()
    (folder / "requirements.txt").write_text("mcp\n")
    return folder


@pytest.fixture
def output_dir(tmp_path):
    out = tmp_path / "cache"
    out.mkdir()
    return out


# --- comando de resolución (uv pip compile) ---------------------------------

def test_resolve_command_includes_all_isolation_protections(target, output_dir):
    _, cmd = build.build_resolve_command(
        target / "requirements.txt", output_dir, python_platform="x86_64-unknown-linux-gnu",
    )

    assert "--rm" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
    assert "--user" in cmd


def test_resolve_command_never_restricts_network():
    """Este es el único paso de `lynceus build` con red permitida: no debe
    llevar `--network`."""
    _, cmd = build.build_resolve_command(
        Path("/some/requirements.txt"), Path("/some/out"), python_platform="x86_64-unknown-linux-gnu",
    )

    assert "--network" not in cmd


def test_resolve_command_sets_python_version_platform_and_flags(target, output_dir):
    _, cmd = build.build_resolve_command(
        target / "requirements.txt", output_dir, python_platform="aarch64-unknown-linux-gnu",
    )

    assert "uv" in cmd and "pip" in cmd and "compile" in cmd
    idx = cmd.index("--python-version")
    assert cmd[idx + 1] == "3.12"
    idx = cmd.index("--python-platform")
    assert cmd[idx + 1] == "aarch64-unknown-linux-gnu"
    assert "--generate-hashes" in cmd
    assert "--no-build" in cmd


def test_resolve_command_without_resolve_date_has_no_exclude_newer(target, output_dir):
    _, cmd = build.build_resolve_command(
        target / "requirements.txt", output_dir, python_platform="x86_64-unknown-linux-gnu",
    )

    assert "--exclude-newer" not in cmd


def test_resolve_command_with_resolve_date_passes_exclude_newer(target, output_dir):
    _, cmd = build.build_resolve_command(
        target / "requirements.txt", output_dir,
        python_platform="x86_64-unknown-linux-gnu", resolve_date="2025-03-22",
    )

    idx = cmd.index("--exclude-newer")
    assert cmd[idx + 1] == "2025-03-22"


def test_resolve_command_mounts_only_requirements_ro_and_output_dir_rw(target, output_dir):
    _, cmd = build.build_resolve_command(
        target / "requirements.txt", output_dir, python_platform="x86_64-unknown-linux-gnu",
    )

    mounts = [arg for i, arg in enumerate(cmd) if cmd[i - 1] == "-v"]
    assert len(mounts) == 2
    assert f"{(target / 'requirements.txt').resolve()}:/resolve/requirements.in:ro" in mounts
    assert f"{output_dir.resolve()}:/resolve/out:rw" in mounts


# --- comando de descarga (pip download) --------------------------------------

def test_download_command_includes_all_isolation_protections(output_dir):
    _, cmd = build.build_download_command(output_dir)

    assert "--rm" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--user" in cmd


def test_download_command_requires_hashes_and_only_binary_without_deps(output_dir):
    _, cmd = build.build_download_command(output_dir)

    assert "--require-hashes" in cmd
    assert "--only-binary=:all:" in cmd
    assert "--no-deps" in cmd


def test_download_command_mounts_only_output_dir(output_dir):
    _, cmd = build.build_download_command(output_dir)

    mounts = [arg for i, arg in enumerate(cmd) if cmd[i - 1] == "-v"]
    assert mounts == [f"{output_dir.resolve()}:/resolve/out:rw"]


# --- Dockerfile de la imagen objetivo ----------------------------------------

def test_render_target_dockerfile_contains_base_image_and_hardening():
    text = build.render_target_dockerfile("lynceus-sandbox:0.1")

    assert text.startswith("FROM lynceus-sandbox:0.1")
    assert "USER root" in text
    assert "/opt/target" in text
    assert "--require-hashes" in text
    assert "--only-binary=:all:" in text
    assert "--no-index" in text
    assert "chown -R sandbox:sandbox /opt/target" in text
    assert text.strip().endswith("USER sandbox")


def test_build_target_image_command_has_no_network(tmp_path):
    cmd = build.build_target_image_command(tmp_path, "lynceus-target:abc123")

    assert "--network" in cmd
    idx = cmd.index("--network")
    assert cmd[idx + 1] == "none"
    assert "-t" in cmd
    idx = cmd.index("-t")
    assert cmd[idx + 1] == "lynceus-target:abc123"
    assert cmd[-1] == str(tmp_path)


# --- etiqueta y versiones -----------------------------------------------------

def test_compute_target_tag_is_sha256_prefix_of_resolved_file(tmp_path):
    resolved = tmp_path / "requirements.resolved.txt"
    resolved.write_text("mcp==1.30.0\n    --hash=sha256:aaaa\n")

    tag = build.compute_target_tag(resolved)

    expected = hashlib.sha256(resolved.read_bytes()).hexdigest()[:12]
    assert tag == f"lynceus-target:{expected}"


def test_parse_pinned_versions_skips_hash_lines_and_comments():
    text = (
        "# generado por uv\n"
        "mcp==1.30.0 \\\n"
        "    --hash=sha256:aaaa\n"
        "requests==2.33.0 \\\n"
        "    --hash=sha256:bbbb\n"
    )

    versions = build.parse_pinned_versions(text)

    assert versions == [("mcp", "1.30.0"), ("requests", "2.33.0")]


# --- caché fuera de la carpeta analizada -------------------------------------

def test_cache_dir_for_default_cache_root_is_never_inside_target(target):
    cache_dir = build.cache_dir_for(target, "requirements.txt", None)

    with pytest.raises(ValueError):
        cache_dir.relative_to(target.resolve())


def test_cache_dir_for_is_deterministic_for_same_inputs(target):
    first = build.cache_dir_for(target, "requirements.txt", "2025-03-22")
    second = build.cache_dir_for(target, "requirements.txt", "2025-03-22")

    assert first == second


def test_cache_dir_for_differs_by_resolve_date(target):
    with_date = build.cache_dir_for(target, "requirements.txt", "2025-03-22")
    without_date = build.cache_dir_for(target, "requirements.txt", None)

    assert with_date != without_date


def test_ensure_cache_dir_outside_target_passes_for_unrelated_cache_dir(target, tmp_path):
    unrelated = tmp_path / "elsewhere" / "cache"

    build.ensure_cache_dir_outside_target(unrelated, target)  # no debe lanzar


def test_ensure_cache_dir_outside_target_rejects_cache_dir_inside_target(target):
    inside = target / ".lynceus-build" / "abc123"

    with pytest.raises(build.BuildError, match="dentro de la carpeta analizada"):
        build.ensure_cache_dir_outside_target(inside, target)


def test_ensure_cache_dir_outside_target_rejects_cache_dir_equal_to_target(target):
    with pytest.raises(build.BuildError):
        build.ensure_cache_dir_outside_target(target, target)


# --- detección de arquitectura ------------------------------------------------

def test_detect_target_platform_maps_arm64(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="arm64\n", stderr="")
    monkeypatch.setattr(build.subprocess, "run", lambda *a, **k: completed)

    assert build.detect_target_platform("lynceus-sandbox:0.1") == "aarch64-unknown-linux-gnu"


def test_detect_target_platform_maps_amd64(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="amd64\n", stderr="")
    monkeypatch.setattr(build.subprocess, "run", lambda *a, **k: completed)

    assert build.detect_target_platform("lynceus-sandbox:0.1") == "x86_64-unknown-linux-gnu"


def test_detect_target_platform_raises_clear_error_on_unknown_arch(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="riscv64\n", stderr="")
    monkeypatch.setattr(build.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(build.BuildError, match="riscv64"):
        build.detect_target_platform("lynceus-sandbox:0.1")


def test_detect_target_platform_raises_when_docker_inspect_fails(monkeypatch):
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="no such image")
    monkeypatch.setattr(build.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(build.BuildError, match="no such image"):
        build.detect_target_platform("lynceus-sandbox:0.1")


def test_detect_target_platform_raises_on_timeout(monkeypatch):
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["docker"], timeout=10)

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    with pytest.raises(build.BuildError):
        build.detect_target_platform("lynceus-sandbox:0.1")


# --- _check_images: Docker en pausa no debe confundirse con "no existe" -----


def test_check_images_raises_a_distinct_error_when_docker_is_not_responding(monkeypatch):
    """Con Docker parado/en pausa, `docker image inspect` falla igual que si
    la imagen no existiera; el error debe distinguir ambos casos (ver
    `_docker_responding`), no sugerir reconstruir una imagen que sí existe."""
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: False)
    monkeypatch.setattr(build, "_image_exists", lambda image: True)

    with pytest.raises(build.BuildError, match="Docker no responde"):
        build._check_images(build.RESOLVER_IMAGE, build.DEFAULT_IMAGE)


def test_check_images_checks_docker_responding_before_image_existence(monkeypatch):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: False)

    def fail_if_called(image):
        raise AssertionError("no debería comprobar si la imagen existe sin Docker respondiendo")

    monkeypatch.setattr(build, "_image_exists", fail_if_called)

    with pytest.raises(build.BuildError, match="Docker no responde"):
        build._check_images(build.RESOLVER_IMAGE, build.DEFAULT_IMAGE)


def test_run_build_exit_is_a_build_error_when_docker_is_not_responding(monkeypatch, target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: False)

    with pytest.raises(build.BuildError, match="Docker no responde"):
        build.run_build(target, "requirements.txt")


# --- orquestación: error por paquete sin binario, sin construir nada --------

def test_run_build_stops_before_docker_build_when_a_dependency_has_no_wheel(monkeypatch, target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "_image_exists", lambda image: True)  # resolver/base ya existen
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(build, "CACHE_ROOT", target.parent / "cache-root")

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "compile" in cmd:
            mount_indices = [i for i, a in enumerate(cmd) if a == "-v"]
            out_dir = Path(cmd[mount_indices[-1] + 1].split(":")[0])
            (out_dir / build.RESOLVED_REQUIREMENTS_NAME).write_text("sinbinario==1.0.0\n")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if "download" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="",
                stderr="ERROR: Could not find a version that satisfies the requirement sinbinario (from -r ...)",
            )
        raise AssertionError(f"comando docker inesperado: {cmd}")

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    with pytest.raises(build.BuildError, match="sinbinario"):
        build.run_build(target, "requirements.txt")

    assert not any("build" in cmd for cmd in calls)


def test_run_build_skips_image_rebuild_when_tag_already_exists(monkeypatch, target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(build, "CACHE_ROOT", target.parent / "cache-root")

    def fake_image_exists(image):
        return True  # tanto la imagen base/resolver como la etiqueta objetivo "existen"

    monkeypatch.setattr(build, "_image_exists", fake_image_exists)

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "compile" in cmd:
            mount_indices = [i for i, a in enumerate(cmd) if a == "-v"]
            out_dir = Path(cmd[mount_indices[-1] + 1].split(":")[0])
            (out_dir / build.RESOLVED_REQUIREMENTS_NAME).write_text("mcp==1.30.0\n")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if "download" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        raise AssertionError(f"comando docker inesperado: {cmd}")

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    result = build.run_build(target, "requirements.txt")

    assert result.skipped_image_build is True
    assert result.versions == [("mcp", "1.30.0")]
    assert not any("build" in cmd for cmd in calls)
