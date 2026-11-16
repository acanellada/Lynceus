from lynceus_sec.validator.payloads import (
    OUTSIDE_DIR,
    build_path_traversal_payloads,
    build_path_traversal_write_payloads,
    build_payloads,
    build_positive_control_payload,
    build_positive_control_write_payload,
)


def test_generates_bare_and_prefixed_variant_per_technique():
    payloads = build_payloads()

    techniques = {p.technique for p in payloads}
    assert any(t.endswith("_bare") for t in techniques)
    assert any(t.endswith("_prefixed") for t in techniques)
    assert len(techniques) == len(payloads)


def test_canary_paths_are_unique_within_one_call():
    payloads = build_payloads()

    canaries = [p.canary_path for p in payloads]
    assert len(canaries) == len(set(canaries))
    assert all(c.startswith("/tmp/") for c in canaries)


def test_canary_paths_are_unique_across_calls():
    first = {p.canary_path for p in build_payloads()}
    second = {p.canary_path for p in build_payloads()}

    assert first.isdisjoint(second)


def test_prefixed_variant_starts_with_innocuous_prefix_bare_does_not():
    payloads = build_payloads()

    for payload in payloads:
        if payload.technique.endswith("_prefixed"):
            assert payload.value.startswith("lynceus")
        else:
            assert not payload.value.startswith("lynceus")


def test_argument_injection_output_payload_contains_its_canary():
    payloads = build_payloads()

    output_payloads = [p for p in payloads if p.technique.startswith("argument_injection_output")]
    assert len(output_payloads) == 2
    for payload in output_payloads:
        assert f"--output={payload.canary_path}" in payload.value


FS_ROOT = "/tmp/lynceus-root"

_TECHNIQUES = {
    "absolute_outside", "dotdot_outside", "dotslash_outside",
    "absolute_sibling", "dotdot_sibling", "symlink",
}


def test_path_traversal_payloads_have_six_techniques():
    payloads = build_path_traversal_payloads(FS_ROOT)

    assert {p.technique for p in payloads} == _TECHNIQUES


def test_path_traversal_canary_path_and_content_are_unique_per_payload():
    payloads = build_path_traversal_payloads(FS_ROOT)

    paths = [p.canary_path for p in payloads]
    contents = [p.canary_content for p in payloads]
    # El canario "symlink" comparte ruta/contenido reales con el que se lee a
    # través del enlace: solo tres canarios independientes (outside, sibling,
    # symlink), aunque haya seis técnicas (dos cargas cada uno para los dos
    # primeros, una para el tercero).
    assert len(set(paths)) == 3
    assert len(set(contents)) == 3


def test_path_traversal_canary_name_and_content_are_independent():
    for payload in build_path_traversal_payloads(FS_ROOT):
        assert payload.canary_content not in payload.canary_path
        assert payload.canary_path not in payload.canary_content
        assert payload.canary_path.rsplit("/", 1)[-1] != payload.canary_content


def test_path_traversal_canaries_are_unique_across_calls():
    first = {p.canary_path for p in build_path_traversal_payloads(FS_ROOT)}
    second = {p.canary_path for p in build_path_traversal_payloads(FS_ROOT)}

    assert first.isdisjoint(second)


def test_outside_canaries_live_under_the_fixed_outside_dir():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    for technique in ("absolute_outside", "dotdot_outside", "dotslash_outside"):
        assert payloads[technique].canary_path.startswith(f"{OUTSIDE_DIR}/")


def test_sibling_canaries_live_under_a_folder_with_the_same_prefix_as_the_limit():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    for technique in ("absolute_sibling", "dotdot_sibling"):
        assert payloads[technique].canary_path.startswith(f"{FS_ROOT}-x/")
        # Hermana, no dentro del límite: el prefijo de cadena coincide pero
        # la ruta no empieza por "<límite>/" (contención real, no de texto).
        assert not payloads[technique].canary_path.startswith(f"{FS_ROOT}/")


def test_absolute_outside_payload_is_the_bare_canary_path():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    assert payloads["absolute_outside"].value == payloads["absolute_outside"].canary_path


def test_absolute_sibling_payload_is_the_bare_canary_path():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    assert payloads["absolute_sibling"].value == payloads["absolute_sibling"].canary_path


def test_dotdot_outside_payload_has_no_double_slash_and_eight_levels():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    bare = payloads["dotdot_outside"]
    assert "//" not in bare.value
    assert bare.value.count("../") == 8
    assert bare.value.endswith(bare.canary_path.removeprefix("/"))


def test_dotslash_outside_payload_is_dotdot_outside_with_a_dotslash_prefix():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    dotdot = payloads["dotdot_outside"]
    dotslash = payloads["dotslash_outside"]
    assert dotslash.value == f"./{dotdot.value}"
    assert "//" not in dotslash.value
    assert dotslash.canary_path == dotdot.canary_path
    assert dotslash.canary_content == dotdot.canary_content


def test_dotdot_sibling_payload_has_no_double_slash_and_eight_levels():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    bare = payloads["dotdot_sibling"]
    assert "//" not in bare.value
    assert bare.value.count("../") == 8
    assert bare.value.endswith(bare.canary_path.removeprefix("/"))


def test_symlink_payload_points_inside_the_limit_at_the_outside_dir():
    payloads = {p.technique: p for p in build_path_traversal_payloads(FS_ROOT)}

    symlink = payloads["symlink"]
    assert symlink.symlink_path.startswith(f"{FS_ROOT}/")
    assert symlink.symlink_target == OUTSIDE_DIR
    assert symlink.canary_path.startswith(f"{OUTSIDE_DIR}/")
    assert symlink.value == f"{symlink.symlink_path}/{symlink.canary_path.rsplit('/', 1)[-1]}"


def test_only_the_symlink_payload_carries_symlink_fields():
    payloads = build_path_traversal_payloads(FS_ROOT)

    for payload in payloads:
        if payload.technique == "symlink":
            assert payload.symlink_path is not None
            assert payload.symlink_target is not None
        else:
            assert payload.symlink_path is None
            assert payload.symlink_target is None


def test_sibling_dir_follows_a_custom_fs_root():
    payloads = {p.technique: p for p in build_path_traversal_payloads("/tmp/otro-limite")}

    assert payloads["absolute_sibling"].canary_path.startswith("/tmp/otro-limite-x/")


def test_build_positive_control_payload_is_a_plain_path_inside_the_limit():
    control = build_positive_control_payload(FS_ROOT)

    assert control.value == control.canary_path
    assert control.canary_path.startswith(f"{FS_ROOT}/")
    assert "../" not in control.value


def test_build_positive_control_payload_canaries_are_unique_across_calls():
    first = build_positive_control_payload(FS_ROOT)
    second = build_positive_control_payload(FS_ROOT)

    assert first.canary_path != second.canary_path
    assert first.canary_content != second.canary_content


# --- build_path_traversal_write_payloads: oráculo de escritura ---

_WRITE_TECHNIQUES = {
    "absolute_outside_write", "dotdot_outside_write", "dotslash_outside_write",
    "absolute_sibling_write", "dotdot_sibling_write", "symlink_write",
}


def test_path_traversal_write_payloads_have_six_techniques():
    payloads = build_path_traversal_write_payloads(FS_ROOT)

    assert {p.technique for p in payloads} == _WRITE_TECHNIQUES


def test_write_target_paths_and_tokens_are_unique_per_payload():
    """A diferencia de la lectura, cada técnica de escritura lleva su propia
    ruta objetivo y su propio token, incluso dentro del mismo grupo
    (outside/sibling): compartir uno entre dos técnicas haría que la
    primera en confirmar deje la ruta creada, y la comprobación de "no debe
    existir todavía" de la segunda la marcaría como inconclusa aunque el
    servidor sea vulnerable por esa vía también (bug real visto en
    filesystem-mcp-server v1.0.0)."""
    payloads = build_path_traversal_write_payloads(FS_ROOT)

    targets = [p.target_path for p in payloads]
    tokens = [p.token for p in payloads]
    assert len(set(targets)) == len(payloads)
    assert len(set(tokens)) == len(payloads)
    assert all(t.startswith("/tmp/") for t in targets)


def test_write_target_paths_are_unique_across_calls():
    first = {p.target_path for p in build_path_traversal_write_payloads(FS_ROOT)}
    second = {p.target_path for p in build_path_traversal_write_payloads(FS_ROOT)}

    assert first.isdisjoint(second)


def test_outside_write_targets_live_under_the_fixed_outside_dir():
    payloads = {p.technique: p for p in build_path_traversal_write_payloads(FS_ROOT)}

    for technique in ("absolute_outside_write", "dotdot_outside_write", "dotslash_outside_write"):
        assert payloads[technique].target_path.startswith(f"{OUTSIDE_DIR}/")


def test_sibling_write_targets_live_under_a_folder_with_the_same_prefix_as_the_limit():
    payloads = {p.technique: p for p in build_path_traversal_write_payloads(FS_ROOT)}

    for technique in ("absolute_sibling_write", "dotdot_sibling_write"):
        assert payloads[technique].target_path.startswith(f"{FS_ROOT}-x/")
        assert not payloads[technique].target_path.startswith(f"{FS_ROOT}/")


def test_absolute_outside_write_payload_is_the_bare_target_path():
    payloads = {p.technique: p for p in build_path_traversal_write_payloads(FS_ROOT)}

    assert payloads["absolute_outside_write"].value == payloads["absolute_outside_write"].target_path


def test_dotdot_outside_write_payload_has_no_double_slash_and_eight_levels():
    payloads = {p.technique: p for p in build_path_traversal_write_payloads(FS_ROOT)}

    bare = payloads["dotdot_outside_write"]
    assert "//" not in bare.value
    assert bare.value.count("../") == 8
    assert bare.value.endswith(bare.target_path.removeprefix("/"))


def test_dotslash_outside_write_payload_has_its_own_target_with_a_dotslash_prefixed_value():
    """dotslash_outside_write ya no comparte ruta/token con
    dotdot_outside_write (ver test_write_target_paths_and_tokens_are_unique_per_payload):
    cada una lleva su propia ruta objetivo, aunque el valor tenga la misma
    forma ("./" + "../" x8 + ruta)."""
    payloads = {p.technique: p for p in build_path_traversal_write_payloads(FS_ROOT)}

    dotdot = payloads["dotdot_outside_write"]
    dotslash = payloads["dotslash_outside_write"]
    assert dotslash.target_path != dotdot.target_path
    assert dotslash.token != dotdot.token
    assert dotslash.value.startswith("./")
    assert "//" not in dotslash.value
    assert dotslash.value.count("../") == 8
    assert dotslash.value.endswith(dotslash.target_path.removeprefix("/"))


def test_symlink_write_points_directly_at_a_not_yet_existing_target_path():
    """Ajuste del usuario: el enlace de escritura apunta directamente a la
    ruta objetivo (no a una carpeta como en lectura), y esa ruta es nueva
    (uuid), nunca creada por el harness: un enlace "colgante"."""
    payloads = {p.technique: p for p in build_path_traversal_write_payloads(FS_ROOT)}

    symlink = payloads["symlink_write"]
    assert symlink.symlink_path is not None
    assert symlink.symlink_path.startswith(f"{FS_ROOT}/")
    # El destino del enlace ES la ruta objetivo, no una carpeta.
    assert symlink.symlink_target == symlink.target_path
    assert symlink.target_path.startswith(f"{OUTSIDE_DIR}/")
    # El valor pasado a la tool es el propio enlace, no "<enlace>/<nombre>".
    assert symlink.value == symlink.symlink_path


def test_only_the_symlink_write_payload_carries_symlink_fields():
    payloads = build_path_traversal_write_payloads(FS_ROOT)

    for payload in payloads:
        if payload.technique == "symlink_write":
            assert payload.symlink_path is not None
            assert payload.symlink_target is not None
        else:
            assert payload.symlink_path is None
            assert payload.symlink_target is None


def test_write_sibling_dir_follows_a_custom_fs_root():
    payloads = {p.technique: p for p in build_path_traversal_write_payloads("/tmp/otro-limite")}

    assert payloads["absolute_sibling_write"].target_path.startswith("/tmp/otro-limite-x/")


def test_build_positive_control_write_payload_is_a_plain_path_inside_the_limit():
    control = build_positive_control_write_payload(FS_ROOT)

    assert control.value == control.target_path
    assert control.target_path.startswith(f"{FS_ROOT}/")
    assert "../" not in control.value


def test_build_positive_control_write_payload_targets_are_unique_across_calls():
    first = build_positive_control_write_payload(FS_ROOT)
    second = build_positive_control_write_payload(FS_ROOT)

    assert first.target_path != second.target_path
    assert first.token != second.token
