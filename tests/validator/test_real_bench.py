import subprocess
import time

from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass
from lynceus_sec.validator import build as build_mod
from lynceus_sec.validator import real_bench
from lynceus_sec.validator.real_bench import RealVersionResult
from lynceus_sec.validator.real_manifest import RealManifest, RealVersion
from lynceus_sec.validator.runner import RunnerError


def _manifest(vuln_class="path_traversal", **overrides):
    data = {
        "id": "cve-test",
        "cve": "CVE-TEST",
        "advisory": "https://example.com/advisory",
        "class": vuln_class,
        "repo": "https://example.com/repo.git",
        "requirements": "requirements.txt",
        "entry": "server.py",
        "versions": [
            {
                "label": "vulnerable",
                "commit": "a" * 40,
                "expected": [{"tool": "read_file_tool", "parameter": "path"}],
            }
        ],
    }
    data.update(overrides)
    return RealManifest.model_validate(data)


def _finding(tool: str, parameter: str) -> Finding:
    return Finding(
        case="x", rule_id="r", vuln_class=VulnClass.PATH_TRAVERSAL, tool=tool, severity="high",
        message="m", validated=True, parameter=parameter,
        reproduction=[ReproductionCall(tool=tool, arguments={})],
    )


def _build_result(tag: str, tmp_path) -> build_mod.BuildResult:
    return build_mod.BuildResult(
        tag=tag, resolved_path=tmp_path / "r.txt", cache_dir=tmp_path, versions=[], skipped_image_build=True,
    )


# --- compare_expected ------------------------------------------------------


def test_compare_expected_exact_match_is_all_tp():
    assert real_bench.compare_expected([("a", "x")], [("a", "x")]) == (1, 0, 0)


def test_compare_expected_unexpected_finding_is_fp():
    assert real_bench.compare_expected([], [("a", "x")]) == (0, 1, 0)


def test_compare_expected_missing_finding_is_fn():
    assert real_bench.compare_expected([("a", "x")], []) == (0, 0, 1)


def test_compare_expected_dedups_before_comparing():
    assert real_bench.compare_expected([("a", "x")], [("a", "x"), ("a", "x")]) == (1, 0, 0)


def test_compare_expected_different_parameter_is_a_distinct_key():
    assert real_bench.compare_expected([("a", "x")], [("a", "y")]) == (0, 1, 1)


# --- _run_one_version -------------------------------------------------------


def _patch_source_and_build(monkeypatch, tmp_path, tag: str):
    monkeypatch.setattr(real_bench.real_source, "clone_repo_once", lambda repo, cache_root=None: tmp_path)
    monkeypatch.setattr(real_bench.real_source, "prepare_version_source", lambda *a, **k: tmp_path)
    monkeypatch.setattr(real_bench.real_source, "commit_date", lambda *a, **k: "2026-01-01")
    monkeypatch.setattr(build_mod, "run_build", lambda target, requirements, **k: _build_result(tag, tmp_path))


def test_run_one_version_success_computes_tp_fp_fn(tmp_path, monkeypatch):
    manifest = _manifest()
    version = manifest.versions[0]
    _patch_source_and_build(monkeypatch, tmp_path, "lynceus-target:aaaaaaaaaaaa")
    monkeypatch.setattr(
        real_bench, "validate_case_for",
        lambda vuln_class: (lambda target, **kwargs: ([_finding("read_file_tool", "path")], [], [])),
    )

    result = real_bench._run_one_version(manifest, version, jobs=1, ctx=None, cache_root=None)

    assert (result.tp, result.fp, result.fn) == (1, 0, 0)
    assert result.image_tag == "lynceus-target:aaaaaaaaaaaa"
    assert result.error is None
    assert result.found == [("read_file_tool", "path")]


def test_run_one_version_build_error_does_not_count_as_fn(tmp_path, monkeypatch):
    """Un error de entorno no dice nada sobre si Lynceus habría encontrado lo
    esperado: no debe sumar a tp/fp/fn (se excluye de las métricas en
    `_assemble_real_result`, ver más abajo)."""
    manifest = _manifest()
    version = manifest.versions[0]
    monkeypatch.setattr(real_bench.real_source, "clone_repo_once", lambda repo, cache_root=None: tmp_path)
    monkeypatch.setattr(real_bench.real_source, "prepare_version_source", lambda *a, **k: tmp_path)
    monkeypatch.setattr(real_bench.real_source, "commit_date", lambda *a, **k: "2026-01-01")

    def fake_run_build(*a, **k):
        raise build_mod.BuildError("boom")

    monkeypatch.setattr(build_mod, "run_build", fake_run_build)

    result = real_bench._run_one_version(manifest, version, jobs=1, ctx=None, cache_root=None)

    assert result.error == "boom"
    assert (result.tp, result.fp, result.fn) == (0, 0, 0)
    assert result.image_tag is None


def test_run_one_version_runner_error_does_not_count_as_fn(tmp_path, monkeypatch):
    manifest = _manifest()
    version = manifest.versions[0]
    _patch_source_and_build(monkeypatch, tmp_path, "lynceus-target:bbbbbbbbbbbb")

    def fake_validate_case_for(vuln_class):
        def fake(target, **kwargs):
            raise RunnerError("docker boom")
        return fake

    monkeypatch.setattr(real_bench, "validate_case_for", fake_validate_case_for)

    result = real_bench._run_one_version(manifest, version, jobs=1, ctx=None, cache_root=None)

    assert result.error == "docker boom"
    assert (result.tp, result.fp, result.fn) == (0, 0, 0)


def test_run_one_version_passes_fs_root_only_for_path_traversal(tmp_path, monkeypatch):
    manifest = _manifest(vuln_class="command_injection")
    version = manifest.versions[0]
    captured: dict = {}
    _patch_source_and_build(monkeypatch, tmp_path, "lynceus-target:cccccccccccc")

    def fake_validate_case_for(vuln_class):
        def fake(target, **kwargs):
            captured.update(kwargs)
            return [], [], []
        return fake

    monkeypatch.setattr(real_bench, "validate_case_for", fake_validate_case_for)
    real_bench._run_one_version(manifest, version, jobs=1, ctx=None, cache_root=None)

    assert "fs_root" not in captured


def test_run_one_version_target_dir_uses_subdir(tmp_path, monkeypatch):
    manifest = _manifest(subdir="nested/dir")
    version = manifest.versions[0]
    captured: dict = {}
    monkeypatch.setattr(real_bench.real_source, "clone_repo_once", lambda repo, cache_root=None: tmp_path)
    monkeypatch.setattr(real_bench.real_source, "prepare_version_source", lambda *a, **k: tmp_path)
    monkeypatch.setattr(real_bench.real_source, "commit_date", lambda *a, **k: "2026-01-01")

    def fake_run_build(target, requirements, **k):
        captured["target"] = target
        return _build_result("lynceus-target:dddddddddddd", tmp_path)

    monkeypatch.setattr(build_mod, "run_build", fake_run_build)
    monkeypatch.setattr(real_bench, "validate_case_for", lambda vc: (lambda target, **k: ([], [], [])))

    real_bench._run_one_version(manifest, version, jobs=1, ctx=None, cache_root=None)

    assert captured["target"] == tmp_path / "nested" / "dir"


# --- aggregation -------------------------------------------------------------


def test_assemble_aggregates_by_class_and_global():
    results = [
        RealVersionResult(
            manifest_id="a", cve="A", vuln_class=VulnClass.PATH_TRAVERSAL, label="v",
            expected=[("t", "p")], found=[("t", "p")], tp=1, fp=0, fn=0,
        ),
        RealVersionResult(
            manifest_id="b", cve="B", vuln_class=VulnClass.SSRF, label="v",
            expected=[("t", "p")], found=[], tp=0, fp=0, fn=1,
        ),
    ]
    result = real_bench._assemble_real_result(results)

    assert result.metrics.by_class[VulnClass.PATH_TRAVERSAL].tp == 1
    assert result.metrics.by_class[VulnClass.SSRF].fn == 1
    assert result.metrics.tp == 1
    assert result.metrics.fn == 1
    assert result.metrics.precision == 1.0


def test_assemble_excludes_errored_versions_from_metrics_and_lists_them():
    results = [
        RealVersionResult(
            manifest_id="a", cve="A", vuln_class=VulnClass.SSRF, label="vulnerable",
            expected=[("fetch", "url")], found=[], error="boom", tp=0, fp=0, fn=0,
        ),
        RealVersionResult(
            manifest_id="b", cve="B", vuln_class=VulnClass.SSRF, label="vulnerable",
            expected=[("fetch", "url")], found=[("fetch", "url")], tp=1, fp=0, fn=0,
        ),
    ]
    result = real_bench._assemble_real_result(results)

    assert (result.metrics.tp, result.metrics.fp, result.metrics.fn) == (1, 0, 0)
    assert result.metrics.by_class[VulnClass.SSRF].fn == 0
    assert [r.manifest_id for r in result.errored] == ["a"]


def test_assemble_tracks_inconclusive_by_class_and_by_case():
    results = [
        RealVersionResult(
            manifest_id="a", cve="A", vuln_class=VulnClass.PATH_TRAVERSAL, label="vulnerable",
            expected=[], found=[], inconclusive=[{"tool": "t"}], tp=0, fp=0, fn=0,
        ),
    ]
    result = real_bench._assemble_real_result(results)

    assert result.inconclusive_by_class == {"path_traversal": 1}
    assert result.inconclusive_by_case == {"a:vulnerable": 1}


def test_run_real_benchmark_parallel_preserves_unit_order(monkeypatch):
    manifests = [_manifest(id=f"cve-{i}") for i in range(5)]
    delays = {f"cve-{i}:vulnerable": (5 - i) * 0.01 for i in range(5)}

    def fake_run_one_version(manifest, version, *, jobs, ctx, cache_root):
        case_id = f"{manifest.id}:{version.label}"
        time.sleep(delays[case_id])
        return RealVersionResult(
            manifest_id=manifest.id, cve=manifest.cve, vuln_class=manifest.vuln_class,
            label=version.label, expected=[], found=[],
        )

    monkeypatch.setattr(real_bench, "_run_one_version", fake_run_one_version)

    result = real_bench.run_real_benchmark(manifests, jobs=3)

    assert [r.case_id for r in result.version_results] == [f"cve-{i}:vulnerable" for i in range(5)]


# --- carrera de clonado compartido (ver real_source) ------------------------


def _init_local_repo_with_two_commits(path):
    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, text=True)

    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    run("config", "user.email", "lynceus-tests@example.com")
    run("config", "user.name", "Lynceus Tests")
    (path / "file.txt").write_text("v1\n")
    run("add", "file.txt")
    run("commit", "-q", "-m", "v1")
    sha1 = run("rev-parse", "HEAD").stdout.strip()
    (path / "other.txt").write_text("v2\n")
    run("add", "other.txt")
    run("commit", "-q", "-m", "v2")
    sha2 = run("rev-parse", "HEAD").stdout.strip()
    return sha1, sha2


def test_two_versions_of_same_repo_with_jobs_above_one_clone_only_once(tmp_path, monkeypatch):
    """Reproduce el caso de `mcp-server-fetch-ssrf-4838`: dos versiones del
    mismo manifiesto comparten `repo`. Con `--jobs` > 1, ambas pueden entrar
    en `clone_repo_once` casi a la vez; el cerrojo de `real_source` debe
    serializarlas para que `git clone` se ejecute una sola vez."""
    from lynceus_sec.validator import real_source

    repo = tmp_path / "source"
    sha1, sha2 = _init_local_repo_with_two_commits(repo)
    cache_root = tmp_path / "cache"

    # `model_construct` (no `model_validate`): `repo` es una ruta local de
    # prueba, no una URL https (eso ya se prueba aparte, en
    # test_real_manifest.py); aquí solo importa el comportamiento de
    # `real_source`/`real_bench` ante un repositorio compartido.
    manifest = RealManifest.model_construct(
        id="shared-repo", cve=None, advisory="https://example.com/advisory",
        vuln_class=VulnClass.PATH_TRAVERSAL, repo=str(repo), subdir=None,
        requirements="file.txt", entry="server.py", pythonpath=[], fs_root=None,
        versions=[
            RealVersion.model_construct(label="v1", commit=sha1, resolve_date=None, expected=[]),
            RealVersion.model_construct(label="v2", commit=sha2, resolve_date=None, expected=[]),
        ],
    )

    clone_calls: list[list[str]] = []
    original_run_git = real_source._run_git

    def slow_run_git(args, *, cwd=None, step):
        if "clone" in args:
            clone_calls.append(args)
            time.sleep(0.1)
        return original_run_git(args, cwd=cwd, step=step)

    monkeypatch.setattr(real_source, "_run_git", slow_run_git)
    monkeypatch.setattr(
        build_mod, "run_build",
        lambda target, requirements, **k: _build_result("lynceus-target:eeeeeeeeeeee", tmp_path),
    )
    monkeypatch.setattr(real_bench, "validate_case_for", lambda vc: (lambda target, **k: ([], [], [])))

    result = real_bench.run_real_benchmark([manifest], jobs=2, cache_root=cache_root)

    assert len(clone_calls) == 1
    assert [r.error for r in result.version_results] == [None, None]
