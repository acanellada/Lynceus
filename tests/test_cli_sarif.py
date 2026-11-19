import json
from pathlib import Path

from lynceus_sec.cli_env import EnvironmentInfo
from lynceus_sec.cli_sarif import CAPABILITY_RULE_ID, SARIF_VERSION, build_sarif_report
from lynceus_sec.core.model import Finding, ReproductionCall, VulnClass

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"

ENV = EnvironmentInfo(
    lynceus_version="0.0.1",
    sandbox_image="lynceus-sandbox:0.1",
    sandbox_image_id="sha256:deadbeef",
    base_image_ref="python:3.12-slim@sha256:aa94",
    declared_python_version="3.12",
    declared_mcp_version="1.30.0",
)


def _finding(**overrides) -> Finding:
    defaults = {
        "case": "x", "rule_id": "cmdi-shell", "vuln_class": VulnClass.COMMAND_INJECTION,
        "tool": "git_log", "severity": "critical", "message": "m", "evidence": "Canario creado en /tmp/x",
        "validated": True, "parameter": "ref", "technique": "shell", "payload": "; id",
        "reproduction": [ReproductionCall(tool="git_log", arguments={"ref": "; id"})],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _build(**overrides) -> dict:
    defaults = {
        "target": "/tmp/case", "classes": ["command_injection"], "fs_root": "/tmp/lynceus-root",
        "findings": [], "inconclusive_by_class": {}, "positive_controls_by_class": {},
        "capabilities_by_class": {}, "elapsed_seconds": 1.0, "environment": ENV,
    }
    defaults.update(overrides)
    return build_sarif_report(**defaults)


def _validator():
    jsonschema = __import__("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    return jsonschema.Draft7Validator(schema)


def test_sarif_report_validates_against_official_schema():
    import pytest

    pytest.importorskip("jsonschema")
    payload = _build(findings=[_finding()])
    validator = _validator()
    errors = list(validator.iter_errors(payload))
    assert errors == []


def test_sarif_report_has_minimal_structure():
    payload = _build(findings=[_finding()])
    assert payload["version"] == SARIF_VERSION
    run = payload["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert rules
    rule_ids = {rule["id"] for rule in rules}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in ("error", "warning", "note", "none")


def test_sarif_report_has_schema_url_column_kind_and_automation_details():
    payload = _build()
    assert payload["$schema"].startswith("https://")
    run = payload["runs"][0]
    assert run["columnKind"] == "utf16CodeUnits"
    assert run["automationDetails"]["id"] == "/tmp/case"


def test_sarif_report_confirmed_vulnerability_produces_error_result_with_rule_id():
    payload = _build(findings=[_finding()])
    results = payload["runs"][0]["results"]
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == "lynceus/command-injection"
    assert result["level"] == "error"
    assert "git_log" in result["message"]["text"]
    assert result["properties"]["parameter"] == "ref"


def test_sarif_report_inconclusive_produces_no_result():
    inconclusive = {"ssrf": [{"tool": "fetch", "parameter": "url", "technique": "t", "detail": "d"}]}
    payload = _build(classes=["ssrf"], findings=[], inconclusive_by_class=inconclusive)
    assert payload["runs"][0]["results"] == []


def test_sarif_report_capability_produces_note_result():
    capabilities = {
        "command_injection": [
            {
                "tool": "run_shell", "parameter": "command", "probe": None,
                "confirmations": [
                    {
                        "technique": "shell_semicolon_bare", "payload": "; touch /tmp/inj",
                        "evidence": "Canario creado en /tmp/inj",
                        "reproduction": [ReproductionCall(tool="run_shell", arguments={"command": "; touch /tmp/inj"})],
                    }
                ],
                "bypassable_filter": False, "blocked_techniques": [],
            }
        ]
    }
    payload = _build(findings=[], capabilities_by_class=capabilities)
    results = payload["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == CAPABILITY_RULE_ID
    assert results[0]["level"] == "note"


def test_sarif_rules_include_help_with_cwe_link():
    payload = _build()
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    expected_cwe_url = {
        "lynceus/command-injection": "https://cwe.mitre.org/data/definitions/78.html",
        "lynceus/path-traversal": "https://cwe.mitre.org/data/definitions/22.html",
        "lynceus/ssrf": "https://cwe.mitre.org/data/definitions/918.html",
    }
    for rule in rules:
        if rule["id"] not in expected_cwe_url:
            continue
        help_ = rule["help"]
        assert help_["text"]
        assert help_["markdown"]
        assert expected_cwe_url[rule["id"]] in help_["text"]
        assert expected_cwe_url[rule["id"]] in help_["markdown"]


def test_capability_rule_help_explains_it_is_not_an_implementation_flaw():
    payload = _build()
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    capability_rule = next(r for r in rules if r["id"] == CAPABILITY_RULE_ID)
    assert "no es un fallo de implementación" in capability_rule["help"]["text"].lower()
    assert "capacidad" in capability_rule["help"]["markdown"].lower()


def test_artifact_location_points_to_default_entry_file():
    payload = _build(findings=[_finding()])
    location = payload["runs"][0]["results"][0]["locations"][0]
    artifact_location = location["physicalLocation"]["artifactLocation"]
    assert artifact_location["uri"] == "/tmp/case/server.py"
    assert "region" not in location["physicalLocation"]


def test_artifact_location_uses_custom_entry():
    payload = _build(findings=[_finding()], entry="src/main.py")
    artifact_location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact_location["uri"] == "/tmp/case/src/main.py"


def test_sarif_root_writes_relative_uri_when_target_is_inside_it():
    payload = _build(findings=[_finding()], target="/tmp/workspace/mycase", sarif_root="/tmp/workspace")
    artifact_location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact_location["uri"] == "mycase/server.py"


def test_without_sarif_root_uri_keeps_full_target_path():
    payload = _build(findings=[_finding()], target="/tmp/workspace/mycase")
    artifact_location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact_location["uri"] == "/tmp/workspace/mycase/server.py"


def test_sarif_root_target_outside_it_keeps_full_path_without_dotdot():
    payload = _build(findings=[_finding()], target="/tmp/other/mycase", sarif_root="/tmp/workspace")
    artifact_location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact_location["uri"] == "/tmp/other/mycase/server.py"
    assert ".." not in artifact_location["uri"]


def test_partial_fingerprints_are_stable_across_identical_calls():
    payload_a = _build(findings=[_finding()])
    payload_b = _build(findings=[_finding()])
    fp_a = payload_a["runs"][0]["results"][0]["partialFingerprints"]
    fp_b = payload_b["runs"][0]["results"][0]["partialFingerprints"]
    assert fp_a == fp_b
    assert fp_a


def test_partial_fingerprints_differ_by_tool_parameter_or_class():
    base = _build(findings=[_finding()])["runs"][0]["results"][0]["partialFingerprints"]

    other_tool = _build(findings=[_finding(tool="other_tool")])["runs"][0]["results"][0]["partialFingerprints"]
    other_parameter = _build(findings=[_finding(parameter="other_param")])["runs"][0]["results"][0][
        "partialFingerprints"
    ]
    other_class = _build(
        classes=["path_traversal"],
        findings=[_finding(vuln_class=VulnClass.PATH_TRAVERSAL, rule_id="ptrav-x")],
    )["runs"][0]["results"][0]["partialFingerprints"]

    assert base != other_tool
    assert base != other_parameter
    assert base != other_class


def test_sarif_report_malicious_tool_name_does_not_break_json():
    malicious = _finding(
        tool='"; DROP TABLE x; --<script>alert(1)</script>\n\t"quoted"\\',
        parameter='weird separator',
        evidence="evidencia con \"comillas\" y \\backslash\\",
    )
    payload = _build(findings=[malicious])
    text = json.dumps(payload, ensure_ascii=False)
    round_tripped = json.loads(text)
    result = round_tripped["runs"][0]["results"][0]
    assert malicious.tool in result["message"]["text"]
    assert result["properties"]["tool"] == malicious.tool
