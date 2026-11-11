from pathlib import Path

import pytest

from lynceus_sec.core.model import VulnClass
from lynceus_sec.validator.real_manifest import load_real_manifest, load_real_manifests

VALID_SHA = "a" * 40


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def _minimal_manifest(**overrides) -> str:
    fields = {
        "id": "cve-0000-0001",
        "cve": "CVE-0000-0001",
        "advisory": "https://example.com/advisory",
        "class": "path_traversal",
        "repo": "https://example.com/repo.git",
        "requirements": "requirements.txt",
        "entry": "server.py",
    }
    fields.update(overrides)
    fields = {key: value for key, value in fields.items() if value is not None}  # None = omitir el campo
    lines = [f'{key} = "{value}"' for key, value in fields.items() if not isinstance(value, list)]
    for key, value in fields.items():
        if isinstance(value, list):
            quoted = ", ".join(f'"{item}"' for item in value)
            lines.append(f"{key} = [{quoted}]")
    lines.append("")
    lines.append("[[versions]]")
    lines.append('label = "vulnerable"')
    lines.append(f'commit = "{VALID_SHA}"')
    lines.append('expected = [{ tool = "read_file_tool", parameter = "path" }]')
    return "\n".join(lines) + "\n"


def test_valid_manifest_loads(tmp_path):
    path = _write(tmp_path, "m.toml", _minimal_manifest())
    manifest = load_real_manifest(path)
    assert manifest.id == "cve-0000-0001"
    assert manifest.vuln_class is VulnClass.PATH_TRAVERSAL
    assert manifest.versions[0].commit == VALID_SHA
    assert manifest.versions[0].expected[0].tool == "read_file_tool"


def test_short_sha_is_rejected(tmp_path):
    text = _minimal_manifest().replace(VALID_SHA, "a" * 39)
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="40 caracteres hexadecimales"):
        load_real_manifest(path)


def test_uppercase_sha_is_rejected(tmp_path):
    text = _minimal_manifest().replace(VALID_SHA, "A" * 40)
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="40 caracteres hexadecimales"):
        load_real_manifest(path)


def test_non_hex_sha_is_rejected(tmp_path):
    text = _minimal_manifest().replace(VALID_SHA, "g" * 40)
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="40 caracteres hexadecimales"):
        load_real_manifest(path)


def test_http_repo_is_rejected(tmp_path):
    text = _minimal_manifest(repo="http://example.com/repo.git")
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="https"):
        load_real_manifest(path)


def test_unknown_class_is_rejected(tmp_path):
    text = _minimal_manifest(**{"class": "sql_injection"})
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError):
        load_real_manifest(path)


_ABSOLUTE_BY_FIELD = {"subdir": "/etc/passwd", "requirements": "/etc/passwd", "entry": "/etc/server.py"}
_DOTDOT_BY_FIELD = {"subdir": "../escape", "requirements": "../escape", "entry": "../escape.py"}


@pytest.mark.parametrize("field", ["subdir", "requirements", "entry"])
def test_absolute_path_fields_are_rejected(tmp_path, field):
    text = _minimal_manifest(**{field: _ABSOLUTE_BY_FIELD[field]})
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="relativo"):
        load_real_manifest(path)


@pytest.mark.parametrize("field", ["subdir", "requirements", "entry"])
def test_dotdot_path_fields_are_rejected(tmp_path, field):
    text = _minimal_manifest(**{field: _DOTDOT_BY_FIELD[field]})
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="relativo"):
        load_real_manifest(path)


def test_entry_must_end_in_py(tmp_path):
    text = _minimal_manifest(entry="server.sh")
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match=r"\.py"):
        load_real_manifest(path)


def test_pythonpath_with_dotdot_is_rejected(tmp_path):
    text = _minimal_manifest(pythonpath=["../outside"])
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="relativo"):
        load_real_manifest(path)


def test_fs_root_must_be_under_tmp(tmp_path):
    text = _minimal_manifest(**{"class": "path_traversal", "fs_root": "/var/lynceus-root"})
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="/tmp"):
        load_real_manifest(path)


def test_fs_root_cannot_be_tmp_itself(tmp_path):
    text = _minimal_manifest(**{"class": "path_traversal", "fs_root": "/tmp"})
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="/tmp mismo"):
        load_real_manifest(path)


def test_invalid_resolve_date_is_rejected(tmp_path):
    text = _minimal_manifest() + '\n[[versions]]\nlabel = "fixed"\ncommit = "' + ("b" * 40) + '"\nresolve_date = "10-11-2026"\n'
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="AAAA-MM-DD"):
        load_real_manifest(path)


def test_duplicate_version_labels_are_rejected(tmp_path):
    text = _minimal_manifest() + f'\n[[versions]]\nlabel = "vulnerable"\ncommit = "{"b" * 40}"\nexpected = []\n'
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="duplicadas"):
        load_real_manifest(path)


def test_no_versions_is_rejected(tmp_path):
    fields = {
        "id": "cve-0000-0001",
        "cve": "CVE-0000-0001",
        "advisory": "https://example.com/advisory",
        "class": "path_traversal",
        "repo": "https://example.com/repo.git",
        "requirements": "requirements.txt",
        "entry": "server.py",
        "versions": [],
    }
    lines = [f'{key} = "{value}"' for key, value in fields.items() if not isinstance(value, list)]
    lines.append("versions = []")
    path = _write(tmp_path, "m.toml", "\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="al menos una versión"):
        load_real_manifest(path)


def test_manifest_without_advisory_is_rejected(tmp_path):
    text = _minimal_manifest(advisory=None)
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="advisory"):
        load_real_manifest(path)


def test_http_advisory_is_rejected(tmp_path):
    text = _minimal_manifest(advisory="http://example.com/advisory")
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError, match="advisory.*https"):
        load_real_manifest(path)


def test_manifest_without_cve_loads_with_cve_none(tmp_path):
    text = _minimal_manifest(cve=None)
    path = _write(tmp_path, "m.toml", text)
    manifest = load_real_manifest(path)
    assert manifest.cve is None
    assert manifest.advisory == "https://example.com/advisory"


def test_unknown_field_is_rejected(tmp_path):
    text = _minimal_manifest() .replace(
        'entry = "server.py"', 'entry = "server.py"\nunexpected_field = "x"'
    )
    path = _write(tmp_path, "m.toml", text)
    with pytest.raises(ValueError):
        load_real_manifest(path)


def test_load_real_manifests_sorts_by_filename(tmp_path):
    _write(tmp_path, "b.toml", _minimal_manifest(id="cve-0000-0002"))
    _write(tmp_path, "a.toml", _minimal_manifest(id="cve-0000-0001"))
    manifests = load_real_manifests(tmp_path)
    assert [m.id for m in manifests] == ["cve-0000-0001", "cve-0000-0002"]
