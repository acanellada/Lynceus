from lynceus_sec.validator.payloads import build_payloads


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
