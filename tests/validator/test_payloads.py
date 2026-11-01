from lynceus_sec.validator.payloads import build_path_traversal_payloads, build_payloads


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


def test_path_traversal_payloads_have_three_techniques():
    payloads = build_path_traversal_payloads()

    assert {p.technique for p in payloads} == {"absolute", "dotdot_bare", "dotdot_dotslash"}


def test_path_traversal_canary_path_and_content_are_unique_per_payload():
    payloads = build_path_traversal_payloads()

    paths = [p.canary_path for p in payloads]
    contents = [p.canary_content for p in payloads]
    assert len(paths) == len(set(paths))
    assert len(contents) == len(set(contents))


def test_path_traversal_canary_name_and_content_are_independent():
    for payload in build_path_traversal_payloads():
        assert payload.canary_content not in payload.canary_path
        assert payload.canary_path not in payload.canary_content
        assert payload.canary_path.rsplit("/", 1)[-1] != payload.canary_content


def test_path_traversal_canaries_are_unique_across_calls():
    first = {p.canary_path for p in build_path_traversal_payloads()}
    second = {p.canary_path for p in build_path_traversal_payloads()}

    assert first.isdisjoint(second)


def test_absolute_payload_is_the_bare_canary_path():
    payloads = {p.technique: p for p in build_path_traversal_payloads()}

    assert payloads["absolute"].value == payloads["absolute"].canary_path


def test_dotdot_payloads_have_no_double_slash_and_eight_levels():
    payloads = {p.technique: p for p in build_path_traversal_payloads()}

    bare = payloads["dotdot_bare"]
    assert "//" not in bare.value
    assert bare.value.count("../") == 8
    assert bare.value.endswith(bare.canary_path.removeprefix("/"))

    dotslash = payloads["dotdot_dotslash"]
    assert dotslash.value == f"./../../../../../../../../{dotslash.canary_path.removeprefix('/')}"
    assert "//" not in dotslash.value
