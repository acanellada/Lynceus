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


def test_resolve_command_disables_cache_and_widens_tmp_without_relaxing_other_protections(target, output_dir):
    """Con HOME=/tmp, uv guardaría su caché dentro del tmpfs: sin --no-cache,
    dependencias grandes (p. ej. mcp-server-fetch) agotan un tmpfs de 16 MB.
    El tmpfs crece solo para este contenedor, sin perder noexec/nosuid/nodev."""
    _, cmd = build.build_resolve_command(
        target / "requirements.txt", output_dir, python_platform="x86_64-unknown-linux-gnu",
    )

    assert "--no-cache" in cmd
    idx = cmd.index("--tmpfs")
    assert cmd[idx + 1] == "/tmp:rw,noexec,nosuid,nodev,size=512m"


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
    assert f"{(target / 'requirements.txt').resolve()}:/resolve/requirements.txt:ro" in mounts
    assert f"{output_dir.resolve()}:/resolve/out:rw" in mounts


# --- nombre de montaje: uv identifica el formato por el nombre del fichero --

def test_resolver_mount_name_keeps_original_name_for_txt():
    assert build.resolver_mount_name(Path("/some/requirements.txt")) == "requirements.txt"


def test_resolver_mount_name_keeps_original_name_for_in():
    assert build.resolver_mount_name(Path("/some/requirements.in")) == "requirements.in"


def test_resolver_mount_name_keeps_original_name_for_pyproject_toml():
    assert build.resolver_mount_name(Path("/some/pyproject.toml")) == "pyproject.toml"


def test_resolver_mount_name_rejects_unknown_extension():
    with pytest.raises(build.BuildError, match="setup.cfg"):
        build.resolver_mount_name(Path("/some/setup.cfg"))


def test_resolver_mount_name_rejects_toml_file_that_is_not_pyproject():
    with pytest.raises(build.BuildError, match="other.toml"):
        build.resolver_mount_name(Path("/some/other.toml"))


def test_resolve_command_mounts_pyproject_toml_with_its_own_name(tmp_path, output_dir):
    target = tmp_path / "target"
    target.mkdir()
    pyproject = target / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\ndependencies = ['mcp']\n")

    _, cmd = build.build_resolve_command(
        pyproject, output_dir, python_platform="x86_64-unknown-linux-gnu",
    )

    mounts = [arg for i, arg in enumerate(cmd) if cmd[i - 1] == "-v"]
    assert f"{pyproject.resolve()}:/resolve/pyproject.toml:ro" in mounts
    assert "/resolve/pyproject.toml" in cmd
    assert "/resolve/requirements.in" not in cmd


def test_resolve_command_raises_clear_error_for_unsupported_requirements_name(tmp_path, output_dir):
    target = tmp_path / "target"
    target.mkdir()
    unsupported = target / "setup.cfg"
    unsupported.write_text("[metadata]\n")

    with pytest.raises(build.BuildError, match="setup.cfg"):
        build.build_resolve_command(
            unsupported, output_dir, python_platform="x86_64-unknown-linux-gnu",
        )


# --- orquestación: formato no soportado se detecta sin tocar Docker --------

def test_run_build_rejects_unsupported_requirements_name_before_touching_docker(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "setup.cfg").write_text("[metadata]\n")

    def fail_if_called(*a, **k):
        raise AssertionError("no debería llamar a Docker con un fichero de requisitos no soportado")

    monkeypatch.setattr(build, "_docker_available", fail_if_called)

    with pytest.raises(build.BuildError, match="setup.cfg"):
        build.run_build(target, "setup.cfg")


# --- comando de descarga (pip download) --------------------------------------

def test_download_command_includes_all_isolation_protections(output_dir):
    _, cmd = build.build_download_command(output_dir)

    assert "--rm" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--security-opt" in cmd and "no-new-privileges" in cmd
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--user" in cmd


def test_download_command_disables_cache_and_widens_tmp_without_relaxing_other_protections(output_dir):
    _, cmd = build.build_download_command(output_dir)

    assert "--no-cache-dir" in cmd
    idx = cmd.index("--tmpfs")
    assert cmd[idx + 1] == "/tmp:rw,noexec,nosuid,nodev,size=512m"


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


def test_render_target_dockerfile_without_dist_info_has_no_extra_copy():
    text = build.render_target_dockerfile("lynceus-sandbox:0.1")

    assert "dist-info" not in text
    assert "chown -R sandbox:sandbox /opt/target" in text


def test_render_target_dockerfile_copies_dist_info_to_venv_site_packages():
    text = build.render_target_dockerfile(
        "lynceus-sandbox:0.1", dist_info_dirname="mcp_server_fetch-2026.10.10.dist-info",
    )

    assert (
        "COPY dist-info/mcp_server_fetch-2026.10.10.dist-info/ "
        "/opt/target/lib/python3.12/site-packages/mcp_server_fetch-2026.10.10.dist-info/"
    ) in text
    # La copia de metadatos va antes del chown final, para que quede con el propietario correcto.
    assert text.index("COPY dist-info/") < text.index("chown -R sandbox:sandbox /opt/target")


# --- metadatos estáticos de pyproject.toml (sin instalar el proyecto) -------

def test_read_pyproject_metadata_reads_static_name_and_version(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'mcp-server-fetch'\nversion = '2026.10.10'\n")

    metadata = build.read_pyproject_metadata(pyproject)

    assert metadata.name == "mcp-server-fetch"
    assert metadata.version == "2026.10.10"
    assert metadata.version_is_fallback is False


def test_read_pyproject_metadata_falls_back_when_version_is_dynamic(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'mcp-server-fetch'\ndynamic = ['version']\n")

    metadata = build.read_pyproject_metadata(pyproject)

    assert metadata.name == "mcp-server-fetch"
    assert metadata.version == build._FALLBACK_VERSION
    assert metadata.version_is_fallback is True


def test_read_pyproject_metadata_falls_back_when_version_is_missing(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'mcp-server-fetch'\n")

    metadata = build.read_pyproject_metadata(pyproject)

    assert metadata.version == build._FALLBACK_VERSION
    assert metadata.version_is_fallback is True


def test_read_pyproject_metadata_raises_clear_error_when_name_is_missing(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nversion = '1.0.0'\n")

    with pytest.raises(build.BuildError, match="\\[project\\].name"):
        build.read_pyproject_metadata(pyproject)


# --- nombre/versión no confiables: validados contra PEP 508/440 antes de ---
# --- usarse en una ruta o en una línea COPY del Dockerfile -----------------

@pytest.mark.parametrize("malicious_name", ["../../etc/passwd", "a/b", "evil\nRUN whoami", "..", "-leading-dash"])
def test_read_pyproject_metadata_rejects_name_that_is_not_pep508(tmp_path, malicious_name):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"[project]\nname = {malicious_name!r}\nversion = '1.0.0'\n")

    with pytest.raises(build.BuildError, match="PEP 508"):
        build.read_pyproject_metadata(pyproject)


@pytest.mark.parametrize("valid_name", ["mcp-server-fetch", "mcp_server.fetch", "a", "A1"])
def test_read_pyproject_metadata_accepts_pep508_names(tmp_path, valid_name):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"[project]\nname = {valid_name!r}\nversion = '1.0.0'\n")

    metadata = build.read_pyproject_metadata(pyproject)

    assert metadata.name == valid_name


@pytest.mark.parametrize(
    "valid_version",
    ["1.0.0", "2026.10.10", "1.0a1", "1.0.post1", "1.0.dev0", "1!1.0", "1.0+local.123"],
)
def test_read_pyproject_metadata_accepts_pep440_versions(tmp_path, valid_version):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"[project]\nname = 'pkg'\nversion = {valid_version!r}\n")

    metadata = build.read_pyproject_metadata(pyproject)

    assert metadata.version == valid_version
    assert metadata.version_is_fallback is False


@pytest.mark.parametrize(
    "malicious_version",
    ["1.0\nRUN rm -rf /", "1.0; rm -rf /", "1.0/../../etc", "not-a-version"],
)
def test_read_pyproject_metadata_falls_back_when_version_is_not_pep440(tmp_path, malicious_version):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"[project]\nname = 'pkg'\nversion = {malicious_version!r}\n")

    metadata = build.read_pyproject_metadata(pyproject)

    assert metadata.version == build._FALLBACK_VERSION
    assert metadata.version_is_fallback is True


def test_read_pyproject_metadata_rejects_name_with_trailing_newline():
    """`$` sin `fullmatch` da por válido un salto de línea final; con
    `fullmatch` (lo que usa `read_pyproject_metadata`) no."""
    assert build._PROJECT_NAME_RE.fullmatch("pkg\n") is None
    assert build._PEP440_VERSION_RE.fullmatch("1.0\n") is None


def test_compute_dist_info_dirname_escapes_name_and_version():
    metadata = build.ProjectMetadata(name="mcp-server-fetch", version="2026.10.10", version_is_fallback=False)

    assert build.compute_dist_info_dirname(metadata) == "mcp_server_fetch-2026.10.10.dist-info"


def test_compute_dist_info_dirname_escapes_fallback_version_plus_sign():
    metadata = build.ProjectMetadata(name="pkg", version="0.0.0+lynceus", version_is_fallback=True)

    assert build.compute_dist_info_dirname(metadata) == "pkg-0.0.0_lynceus.dist-info"


def test_render_dist_info_contents_has_only_minimal_metadata_and_installer():
    metadata = build.ProjectMetadata(name="mcp-server-fetch", version="2026.10.10", version_is_fallback=False)

    contents = build.render_dist_info_contents(metadata)

    assert set(contents) == {
        "mcp_server_fetch-2026.10.10.dist-info/METADATA",
        "mcp_server_fetch-2026.10.10.dist-info/INSTALLER",
    }
    metadata_text = contents["mcp_server_fetch-2026.10.10.dist-info/METADATA"]
    assert "Name: mcp-server-fetch" in metadata_text
    assert "Version: 2026.10.10" in metadata_text
    assert contents["mcp_server_fetch-2026.10.10.dist-info/INSTALLER"] == "lynceus\n"
    assert "entry_points" not in metadata_text.lower()


def test_write_dist_info_contents_writes_files_under_staging_dirname(tmp_path):
    contents = {"pkg-1.0.dist-info/METADATA": "Name: pkg\nVersion: 1.0\n"}

    build.write_dist_info_contents(tmp_path, contents)

    written = tmp_path / build.DIST_INFO_STAGING_DIRNAME / "pkg-1.0.dist-info" / "METADATA"
    assert written.read_text() == "Name: pkg\nVersion: 1.0\n"


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

_DOCKERFILE_TEXT = "FROM lynceus-sandbox:0.1\n...\n"


def test_compute_target_tag_is_sha256_prefix_of_normalized_pin_lines_and_dockerfile(tmp_path):
    resolved = tmp_path / "requirements.resolved.txt"
    resolved.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")

    tag = build.compute_target_tag(resolved, _DOCKERFILE_TEXT)

    expected = hashlib.sha256(
        ("mcp==1.30.0 \\\n    --hash=sha256:aaaa" + "\0" + _DOCKERFILE_TEXT).encode()
    ).hexdigest()[:12]
    assert tag == f"lynceus-target:{expected}"


def test_compute_target_tag_ignores_uv_header_comment(tmp_path):
    pins = "mcp==1.30.0 \\\n    --hash=sha256:aaaa\n"
    without_header = tmp_path / "a.txt"
    without_header.write_text(pins)
    with_header = tmp_path / "b.txt"
    with_header.write_text(
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile /resolve/requirements.txt --python-version 3.12\n"
        + pins
    )

    assert build.compute_target_tag(without_header, _DOCKERFILE_TEXT) == build.compute_target_tag(
        with_header, _DOCKERFILE_TEXT
    )


def test_compute_target_tag_ignores_via_annotations(tmp_path):
    without_via = tmp_path / "a.txt"
    without_via.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")
    with_via = tmp_path / "b.txt"
    with_via.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n    # via -r requirements.txt\n")

    assert build.compute_target_tag(without_via, _DOCKERFILE_TEXT) == build.compute_target_tag(
        with_via, _DOCKERFILE_TEXT
    )


def test_compute_target_tag_changes_when_a_version_changes(tmp_path):
    a = tmp_path / "a.txt"
    a.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")
    b = tmp_path / "b.txt"
    b.write_text("mcp==1.31.0 \\\n    --hash=sha256:aaaa\n")

    assert build.compute_target_tag(a, _DOCKERFILE_TEXT) != build.compute_target_tag(b, _DOCKERFILE_TEXT)


def test_compute_target_tag_changes_when_a_hash_changes(tmp_path):
    a = tmp_path / "a.txt"
    a.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")
    b = tmp_path / "b.txt"
    b.write_text("mcp==1.30.0 \\\n    --hash=sha256:bbbb\n")

    assert build.compute_target_tag(a, _DOCKERFILE_TEXT) != build.compute_target_tag(b, _DOCKERFILE_TEXT)


def test_compute_target_tag_changes_when_dockerfile_text_changes(tmp_path):
    resolved = tmp_path / "requirements.resolved.txt"
    resolved.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")

    a = build.compute_target_tag(resolved, "FROM lynceus-sandbox:0.1\n")
    b = build.compute_target_tag(resolved, "FROM lynceus-sandbox:0.2\n")

    assert a != b


def test_compute_target_tag_changes_when_dist_info_contents_change(tmp_path):
    resolved = tmp_path / "requirements.resolved.txt"
    resolved.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")

    a = build.compute_target_tag(resolved, _DOCKERFILE_TEXT, {"pkg-1.0.dist-info/METADATA": "Name: pkg\n"})
    b = build.compute_target_tag(resolved, _DOCKERFILE_TEXT, {"pkg-2.0.dist-info/METADATA": "Name: pkg\n"})
    without_dist_info = build.compute_target_tag(resolved, _DOCKERFILE_TEXT)

    assert a != b
    assert a != without_dist_info
    assert without_dist_info == build.compute_target_tag(resolved, _DOCKERFILE_TEXT, {})


def test_compute_target_tag_stable_for_same_dockerfile_and_dist_info(tmp_path):
    resolved = tmp_path / "requirements.resolved.txt"
    resolved.write_text("mcp==1.30.0 \\\n    --hash=sha256:aaaa\n")
    dist_info = {"pkg-1.0.dist-info/METADATA": "Name: pkg\n", "pkg-1.0.dist-info/INSTALLER": "lynceus\n"}

    first = build.compute_target_tag(resolved, _DOCKERFILE_TEXT, dist_info)
    second = build.compute_target_tag(resolved, _DOCKERFILE_TEXT, dict(dist_info))

    assert first == second


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


# --- _run_or_raise: un timeout no debe perder la salida ya capturada --------

def test_run_or_raise_includes_partial_output_captured_before_timeout(monkeypatch):
    """`subprocess.run` adjunta a `TimeoutExpired` lo ya leído de stdout/stderr
    (siempre en bytes, incluso con `text=True`); antes se descartaba, dejando
    'no terminó en Ns' sin ninguna pista de dónde se quedó colgado."""
    exc = subprocess.TimeoutExpired(cmd=["docker"], timeout=120.0)
    exc.stdout = b"Resolved 10 packages\nDownloading foo-1.0.0.whl\n"
    exc.stderr = b""

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        raise exc

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    with pytest.raises(build.BuildError, match="Downloading foo-1.0.0.whl"):
        build._run_or_raise(["docker", "run"], "some-container", "La resolución de dependencias", timeout=120.0)


def test_run_or_raise_timeout_without_any_output_says_so_explicitly(monkeypatch):
    exc = subprocess.TimeoutExpired(cmd=["docker"], timeout=120.0)
    exc.stdout = b""
    exc.stderr = b""

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        raise exc

    monkeypatch.setattr(build.subprocess, "run", fake_run)

    with pytest.raises(build.BuildError, match="sin salida capturada"):
        build._run_or_raise(["docker", "run"], "some-container", "La resolución de dependencias", timeout=120.0)


def test_decode_partial_output_keeps_only_the_tail():
    text = "\n".join(f"line {i}" for i in range(30)).encode()

    decoded = build._decode_partial_output(text)

    assert "line 29" in decoded
    assert "line 0" not in decoded


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
        build.run_build(target, "requirements.txt", cache_root=target.parent / "cache-root")

    assert not any("build" in cmd for cmd in calls)


def test_run_build_skips_image_rebuild_when_tag_already_exists(monkeypatch, target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")

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

    result = build.run_build(target, "requirements.txt", cache_root=target.parent / "cache-root")

    assert result.skipped_image_build is True
    assert result.versions == [("mcp", "1.30.0")]
    assert not any("build" in cmd for cmd in calls)


# --- orquestación: pyproject.toml genera metadatos sintéticos --------------

@pytest.fixture
def pyproject_target(tmp_path):
    folder = tmp_path / "target"
    folder.mkdir()
    (folder / "pyproject.toml").write_text(
        "[project]\nname = 'mcp-server-fetch'\nversion = '2026.10.10'\ndependencies = ['mcp']\n"
    )
    return folder


def _fake_run_for_pyproject_build(resolved_text: str):
    """Responde a `compile`/`download`/`build` como Docker, sin tocarlo: solo
    escribe el fichero resuelto en el directorio de salida montado."""
    def fake_run(cmd, **kwargs):
        if "compile" in cmd:
            mount_indices = [i for i, a in enumerate(cmd) if a == "-v"]
            out_dir = Path(cmd[mount_indices[-1] + 1].split(":")[0])
            (out_dir / build.RESOLVED_REQUIREMENTS_NAME).write_text(resolved_text)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if "download" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if cmd[:2] == ["docker", "build"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        raise AssertionError(f"comando docker inesperado: {cmd}")
    return fake_run


def test_run_build_from_pyproject_generates_dist_info_and_copies_it_in_dockerfile(monkeypatch, pyproject_target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")

    # La imagen objetivo (etiqueta calculada) no existe todavía; resolver/base sí.
    monkeypatch.setattr(build, "_image_exists", lambda image: not image.startswith("lynceus-target:"))

    monkeypatch.setattr(build.subprocess, "run", _fake_run_for_pyproject_build("mcp==1.30.0\n"))

    result = build.run_build(pyproject_target, "pyproject.toml", cache_root=pyproject_target.parent / "cache-root")

    assert result.warnings == []
    dockerfile_text = (result.cache_dir / build.DOCKERFILE_NAME).read_text()
    assert (
        "COPY dist-info/mcp_server_fetch-2026.10.10.dist-info/ "
        "/opt/target/lib/python3.12/site-packages/mcp_server_fetch-2026.10.10.dist-info/"
    ) in dockerfile_text

    metadata_file = (
        result.cache_dir / build.DIST_INFO_STAGING_DIRNAME
        / "mcp_server_fetch-2026.10.10.dist-info" / "METADATA"
    )
    assert "Name: mcp-server-fetch" in metadata_file.read_text()
    assert "Version: 2026.10.10" in metadata_file.read_text()


def test_run_build_warns_when_pyproject_version_is_dynamic(monkeypatch, tmp_path):
    folder = tmp_path / "target"
    folder.mkdir()
    (folder / "pyproject.toml").write_text(
        "[project]\nname = 'mcp-server-fetch'\ndynamic = ['version']\ndependencies = ['mcp']\n"
    )

    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(build, "_image_exists", lambda image: not image.startswith("lynceus-target:"))
    monkeypatch.setattr(build.subprocess, "run", _fake_run_for_pyproject_build("mcp==1.30.0\n"))

    result = build.run_build(folder, "pyproject.toml", cache_root=tmp_path / "cache-root")

    assert len(result.warnings) == 1
    assert "mcp-server-fetch" in result.warnings[0]
    assert build._FALLBACK_VERSION in result.warnings[0]


def test_run_build_raises_clear_error_before_docker_when_pyproject_has_no_name(monkeypatch, tmp_path):
    folder = tmp_path / "target"
    folder.mkdir()
    (folder / "pyproject.toml").write_text("[project]\nversion = '1.0.0'\ndependencies = ['mcp']\n")

    def fail_if_called(*a, **k):
        raise AssertionError("no debería llamar a Docker si falta [project].name")

    monkeypatch.setattr(build, "_docker_available", fail_if_called)

    with pytest.raises(build.BuildError, match=r"\[project\].name"):
        build.run_build(folder, "pyproject.toml", cache_root=tmp_path / "cache-root")


@pytest.mark.parametrize("malicious_name", ["../../etc/passwd", "a/b", "evil\nRUN whoami"])
def test_run_build_raises_before_docker_when_pyproject_name_is_malicious(monkeypatch, tmp_path, malicious_name):
    """El nombre del proyecto viene del servidor analizado (no confiable) y
    acaba en una ruta de fichero y en una línea COPY del Dockerfile; debe
    rechazarse antes de tocar Docker, no solo escaparse al construir la ruta."""
    folder = tmp_path / "target"
    folder.mkdir()
    (folder / "pyproject.toml").write_text(
        f"[project]\nname = {malicious_name!r}\nversion = '1.0.0'\ndependencies = ['mcp']\n"
    )

    def fail_if_called(*a, **k):
        raise AssertionError("no debería llamar a Docker con un [project].name inválido")

    monkeypatch.setattr(build, "_docker_available", fail_if_called)

    with pytest.raises(build.BuildError, match="PEP 508"):
        build.run_build(folder, "pyproject.toml", cache_root=tmp_path / "cache-root")


def test_run_build_malicious_version_falls_back_and_never_reaches_dockerfile_or_dist_info(monkeypatch, tmp_path):
    """Una versión con un salto de línea seguido de una instrucción de
    Dockerfile (`RUN ...`) no debe llegar nunca a METADATA ni al Dockerfile
    generado: debe caer en el mismo fallback que una versión ausente."""
    folder = tmp_path / "target"
    folder.mkdir()
    payload = "1.0\nRUN rm -rf /"
    (folder / "pyproject.toml").write_text(
        f"[project]\nname = 'mcp-server-fetch'\nversion = {payload!r}\ndependencies = ['mcp']\n"
    )

    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(build, "_image_exists", lambda image: not image.startswith("lynceus-target:"))
    monkeypatch.setattr(build.subprocess, "run", _fake_run_for_pyproject_build("mcp==1.30.0\n"))

    result = build.run_build(folder, "pyproject.toml", cache_root=tmp_path / "cache-root")

    assert len(result.warnings) == 1
    dockerfile_text = (result.cache_dir / build.DOCKERFILE_NAME).read_text()
    assert payload not in dockerfile_text
    assert "RUN rm -rf /\n" not in dockerfile_text  # ninguna RUN inyectada, solo las dos propias de la receta

    dist_info_dir = result.cache_dir / build.DIST_INFO_STAGING_DIRNAME
    for metadata_path in dist_info_dir.rglob("METADATA"):
        metadata_text = metadata_path.read_text()
        assert payload not in metadata_text
        assert f"Version: {build._FALLBACK_VERSION}" in metadata_text


def test_run_build_tag_is_stable_across_repeated_runs_with_pyproject(monkeypatch, pyproject_target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(build, "_image_exists", lambda image: not image.startswith("lynceus-target:"))
    monkeypatch.setattr(build.subprocess, "run", _fake_run_for_pyproject_build("mcp==1.30.0\n"))

    first = build.run_build(pyproject_target, "pyproject.toml", cache_root=pyproject_target.parent / "cache-root-1")
    second = build.run_build(pyproject_target, "pyproject.toml", cache_root=pyproject_target.parent / "cache-root-2")

    assert first.tag == second.tag


def test_run_build_tag_does_not_change_when_only_resolved_file_comments_change(monkeypatch, pyproject_target):
    monkeypatch.setattr(build, "_docker_available", lambda: True)
    monkeypatch.setattr(build, "_docker_responding", lambda: True)
    monkeypatch.setattr(build, "detect_target_platform", lambda image: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(build, "_image_exists", lambda image: not image.startswith("lynceus-target:"))

    monkeypatch.setattr(
        build.subprocess, "run",
        _fake_run_for_pyproject_build("# This file was autogenerated by uv\nmcp==1.30.0\n"),
    )
    with_comment = build.run_build(
        pyproject_target, "pyproject.toml", cache_root=pyproject_target.parent / "cache-root-a",
    )

    monkeypatch.setattr(build.subprocess, "run", _fake_run_for_pyproject_build("mcp==1.30.0\n"))
    without_comment = build.run_build(
        pyproject_target, "pyproject.toml", cache_root=pyproject_target.parent / "cache-root-b",
    )

    assert with_comment.tag == without_comment.tag
