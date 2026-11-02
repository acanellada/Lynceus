from lynceus_sec.cli_env import collect_environment_info


def test_declared_versions_are_read_from_sandbox_files():
    info = collect_environment_info()

    assert info.declared_python_version == "3.12"
    assert info.declared_mcp_version == "1.30.0"
    assert info.base_image_ref is not None
    assert info.base_image_ref.startswith("python:3.12-slim@sha256:")


def test_missing_image_yields_no_image_id():
    info = collect_environment_info(image="lynceus-image-that-does-not-exist:0.0")

    assert info.sandbox_image_id is None
    assert info.sandbox_image == "lynceus-image-that-does-not-exist:0.0"


def test_lynceus_version_is_installed_package_version():
    info = collect_environment_info()

    assert info.lynceus_version != ""
