"""
Tests for ace-manifest.yaml loading and manifest-based matching.
"""
import tempfile
import os
from delta_engine.manifest_loader import load_manifest
from delta_engine.matcher import match_rpm_to_gpm
from delta_engine.engine import compute_all_deltas
from schemas.models import (
    RPM, GPM, AttachedPolicy, Statement, SDKCall,
    Confidence, MatchMethod
)


def make_rpm(service_name: str) -> RPM:
    return RPM(
        service_name=service_name,
        language="python",
        commit_sha="abc123",
        sdk_calls=[
            SDKCall(
                service="s3",
                action="get_object",
                action_iam="s3:GetObject",
                resources=["*"],
                resources_wildcard=True,
                confidence=Confidence.HIGH,
            )
        ],
    )


def make_gpm(role_name: str, role_arn: str) -> GPM:
    return GPM(
        role_name=role_name,
        role_arn=role_arn,
        created_by=None,
        last_modified_pr=None,
        attached_policies=[
            AttachedPolicy(
                policy_arn="arn:aws:iam::123:policy/test",
                statements=[
                    Statement(
                        effect="Allow",
                        actions=["s3:GetObject", "s3:DeleteBucket"],
                        actions_expanded=["s3:GetObject", "s3:DeleteBucket"],
                        actions_wildcard=False,
                        resources=["*"],
                        resources_wildcard=True,
                    )
                ],
            )
        ],
    )


def test_manifest_loads_valid_yaml():
    content = """
version: "1.0"
mappings:
  - service: payments-worker
    role_arn: arn:aws:iam::123:role/payments-prod-role
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        result = load_manifest(path)
        assert result == {"payments-worker": "arn:aws:iam::123:role/payments-prod-role"}
    finally:
        os.unlink(path)


def test_manifest_returns_empty_for_missing_file():
    result = load_manifest("/nonexistent/path/ace-manifest.yaml")
    assert result == {}


def test_manifest_returns_empty_for_empty_mappings():
    content = "version: '1.0'\nmappings: []\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        result = load_manifest(path)
        assert result == {}
    finally:
        os.unlink(path)


def test_manifest_match_takes_priority_over_fuzzy():
    rpm = make_rpm("payments-worker")
    gpm = make_gpm("totally-unrelated-role", "arn:aws:iam::123:role/payments-prod-role")
    manifest = {"payments-worker": "arn:aws:iam::123:role/payments-prod-role"}

    matched_gpm, method = match_rpm_to_gpm(rpm, [gpm], manifest)
    assert method == MatchMethod.MANIFEST
    assert matched_gpm.role_arn == "arn:aws:iam::123:role/payments-prod-role"


def test_manifest_ambiguous_when_role_arn_not_in_gpms():
    rpm = make_rpm("payments-worker")
    gpm = make_gpm("some-role", "arn:aws:iam::123:role/different-role")
    manifest = {"payments-worker": "arn:aws:iam::123:role/payments-prod-role"}

    matched_gpm, method = match_rpm_to_gpm(rpm, [gpm], manifest)
    assert method == MatchMethod.AMBIGUOUS
    assert matched_gpm is None


def test_no_manifest_falls_back_to_fuzzy():
    rpm = make_rpm("sample-lambda")
    gpm = make_gpm("sample-lambda-role", "arn:aws:iam::123:role/sample-lambda-role")

    matched_gpm, method = match_rpm_to_gpm(rpm, [gpm], manifest=None)
    assert method == MatchMethod.FUZZY_NAME


def test_compute_all_deltas_uses_manifest():
    rpm = make_rpm("payments-worker")
    gpm = make_gpm("totally-unrelated-role", "arn:aws:iam::123:role/payments-prod-role")
    manifest = {"payments-worker": "arn:aws:iam::123:role/payments-prod-role"}

    results = compute_all_deltas(rpm, [gpm], manifest)
    assert len(results) == 1
    assert results[0].matched_by == MatchMethod.MANIFEST
    assert any(e.action_iam == "s3:DeleteBucket" for e in results[0].excess)