import subprocess
from pathlib import Path

import pytest

from lynceus_sec.validator import clean

# --- validaciones puras, sin listar ni borrar nada --------------------------

def test_ensure_docker_responding_does_nothing_when_docker_responds(monkeypatch):
    monkeypatch.setattr(clean, "_docker_responding", lambda: True)

    assert clean.ensure_docker_responding() is None


def test_ensure_docker_responding_raises_when_docker_does_not_respond(monkeypatch):
    monkeypatch.setattr(clean, "_docker_responding", lambda: False)

    with pytest.raises(clean.CleanError, match="Docker no responde"):
        clean.ensure_docker_responding()


def test_ensure_cache_removal_is_safe_returns_the_build_path_without_deleting(monkeypatch, tmp_path):
    cache_base = tmp_path / "cache-base"
    build_dir = cache_base / "build"
    build_dir.mkdir(parents=True)
    (build_dir / "marker").write_text("x")
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(cache_base))

    returned = clean.ensure_cache_removal_is_safe()

    assert returned == build_dir
    assert build_dir.exists()  # solo valida, no borra


def test_ensure_cache_removal_is_safe_raises_when_cache_base_is_home(monkeypatch, tmp_path):
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    with pytest.raises(clean.CleanError, match="directorio personal"):
        clean.ensure_cache_removal_is_safe()


# --- listado de imágenes ----------------------------------------------------

def test_list_target_images_parses_tag_and_size(monkeypatch):
    monkeypatch.setattr(clean, "_docker_responding", lambda: True)
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="lynceus-target:abcdef123456\t123MB\n", stderr="",
    )
    monkeypatch.setattr(clean.subprocess, "run", lambda *a, **k: completed)

    images = clean.list_target_images()

    assert images == [clean.TargetImage(tag="lynceus-target:abcdef123456", size="123MB")]


def test_list_target_images_filters_non_matching_tags_as_defense_in_depth(monkeypatch):
    """Si el filtro de `docker images` alguna vez devolviera algo que no case
    con el patrón exacto de lynceus-target, se descarta aquí también."""
    monkeypatch.setattr(clean, "_docker_responding", lambda: True)
    completed = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="lynceus-sandbox:0.1\t50MB\nlynceus-target:abcdef123456\t123MB\n",
        stderr="",
    )
    monkeypatch.setattr(clean.subprocess, "run", lambda *a, **k: completed)

    images = clean.list_target_images()

    assert [image.tag for image in images] == ["lynceus-target:abcdef123456"]


def test_list_target_images_empty_when_no_output(monkeypatch):
    monkeypatch.setattr(clean, "_docker_responding", lambda: True)
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    monkeypatch.setattr(clean.subprocess, "run", lambda *a, **k: completed)

    assert clean.list_target_images() == []


def test_list_target_images_raises_clear_error_when_docker_not_responding(monkeypatch):
    monkeypatch.setattr(clean, "_docker_responding", lambda: False)

    with pytest.raises(clean.CleanError, match="Docker no responde"):
        clean.list_target_images()


def test_list_target_images_raises_on_docker_failure(monkeypatch):
    monkeypatch.setattr(clean, "_docker_responding", lambda: True)
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
    monkeypatch.setattr(clean.subprocess, "run", lambda *a, **k: completed)

    with pytest.raises(clean.CleanError, match="boom"):
        clean.list_target_images()


# --- borrado de imágenes -----------------------------------------------------

def test_remove_images_reports_removed_and_failed(monkeypatch):
    def fake_run(cmd, **kwargs):
        tag = cmd[-1]
        returncode = 0 if tag == "lynceus-target:aaaaaaaaaaaa" else 1
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(clean.subprocess, "run", fake_run)

    removed, failed = clean.remove_images(["lynceus-target:aaaaaaaaaaaa", "lynceus-target:bbbbbbbbbbbb"])

    assert removed == ["lynceus-target:aaaaaaaaaaaa"]
    assert failed == ["lynceus-target:bbbbbbbbbbbb"]


def test_remove_images_empty_list_calls_docker_zero_times(monkeypatch):
    calls = []
    monkeypatch.setattr(clean.subprocess, "run", lambda *a, **k: calls.append(a))

    removed, failed = clean.remove_images([])

    assert removed == []
    assert failed == []
    assert calls == []


# --- seguridad de la caché: solo se borra la subcarpeta build --------------

def test_remove_cache_dir_removes_only_the_build_subfolder(monkeypatch, tmp_path):
    cache_base = tmp_path / "cache-base"
    build_dir = cache_base / "build"
    build_dir.mkdir(parents=True)
    (build_dir / "marker").write_text("x")
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(cache_base))

    removed = clean.remove_cache_dir()

    assert removed == build_dir
    assert not build_dir.exists()
    assert cache_base.exists()  # la base de la caché sigue ahí, solo se borró "build"


def test_remove_cache_dir_is_a_noop_when_it_does_not_exist(monkeypatch, tmp_path):
    cache_base = tmp_path / "cache-base"
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(cache_base))

    assert clean.remove_cache_dir() is None


def test_remove_cache_dir_refuses_when_cache_base_is_the_home_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    rmtree_calls = []
    monkeypatch.setattr(clean.shutil, "rmtree", lambda path: rmtree_calls.append(path))

    with pytest.raises(clean.CleanError, match="directorio personal"):
        clean.remove_cache_dir()

    assert rmtree_calls == []


def test_remove_cache_dir_refuses_when_cache_base_is_filesystem_root(monkeypatch):
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", "/")
    rmtree_calls = []
    monkeypatch.setattr(clean.shutil, "rmtree", lambda path: rmtree_calls.append(path))

    with pytest.raises(clean.CleanError, match="raíz del sistema de ficheros"):
        clean.remove_cache_dir()

    assert rmtree_calls == []


def test_ensure_safe_build_cache_dir_refuses_a_path_that_is_not_the_build_subfolder(monkeypatch, tmp_path):
    monkeypatch.setenv("LYNCEUS_CACHE_DIR", str(tmp_path))

    with pytest.raises(clean.CleanError, match="build"):
        clean._ensure_safe_build_cache_dir(tmp_path / "not-build")
