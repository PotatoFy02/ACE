"""
Delta Engine tests — 8 tests covering core contract.
All against synthetic fixtures — no real files.
"""

import pytest
from schemas.models import (
    RPM, GPM, SDKCall, Statement, AttachedPolicy,
    Confidence, Severity, MatchMethod, OverPrivilegeType
)
from delta_engine.engine import compute_delta, compute_all_deltas
from delta_engine.severity_map import get_severity
from delta_engine.matcher import match_rpm_to_gpm


# --- Fixtures ---

def make_rpm(service_name="sample-lambda", calls=None) -> RPM:
    calls = calls or [
        SDKCall(
            service="s3", action="get_object", action_iam="s3:GetObject",
            resources=["arn:aws:s3:::my-bucket/*"],
            resources_wildcard=False, confidence=Confidence.HIGH
        )
    ]
    return RPM(
        service_name=service_name,
        language="python",
        commit_sha="abc123",
        sdk_calls=calls
    )


def make_gpm(role_name="sample-lambda-role", actions=None, resources=None) -> GPM:
    actions = actions or ["s3:GetObject", "s3:DeleteBucket", "s3:PutObject"]
    resources = resources or ["*"]
    return GPM(
        role_name=role_name,
        role_arn=f"arn:aws:iam::123456789:role/{role_name}",
        created_by=None,
        last_modified_pr=None,
        attached_policies=[
            AttachedPolicy(
                policy_arn="arn:aws:iam::local:policy/test-policy",
                statements=[
                    Statement(
                        effect="Allow",
                        actions=actions,
                        actions_expanded=actions,
                        actions_wildcard=False,
                        resources=resources,
                        resources_wildcard="*" in resources
                    )
                ]
            )
        ]
    )


# --- Tests ---

def test_excess_actions_identified():
    rpm = make_rpm(calls=[
        SDKCall(
            service="s3", action="get_object", action_iam="s3:GetObject",
            resources=["*"], resources_wildcard=True, confidence=Confidence.HIGH
        )
    ])
    gpm = make_gpm(actions=["s3:GetObject", "s3:DeleteBucket", "s3:PutObject"],
                   resources=["*"])
    result = compute_delta(rpm, [gpm])
    excess_actions = {e.action_iam for e in result.excess
                      if e.over_privilege_type == OverPrivilegeType.ACTION}
    assert "s3:DeleteBucket" in excess_actions
    assert "s3:PutObject" in excess_actions
    assert "s3:GetObject" not in excess_actions


def test_delete_bucket_is_high_severity():
    assert get_severity("s3:DeleteBucket") == Severity.HIGH


def test_iam_create_role_is_high_severity():
    assert get_severity("iam:CreateRole") == Severity.HIGH


def test_s3_get_object_is_low_severity():
    assert get_severity("s3:GetObject") == Severity.LOW


def test_low_confidence_sets_requires_human_review():
    rpm = make_rpm(calls=[
        SDKCall(
            service="s3", action="get_object", action_iam="s3:GetObject",
            resources=["*"], resources_wildcard=True, confidence=Confidence.LOW
        )
    ])
    gpm = make_gpm()
    result = compute_delta(rpm, [gpm])
    assert result.requires_human_review is True


def test_no_excess_produces_green_patch_risk():
    rpm = make_rpm(calls=[
        SDKCall(
            service="s3", action="get_object", action_iam="s3:GetObject",
            resources=["*"], resources_wildcard=True, confidence=Confidence.HIGH
        )
    ])
    gpm = make_gpm(actions=["s3:GetObject"], resources=["*"])
    result = compute_delta(rpm, [gpm])
    assert result.patch_risk == "green"
    assert len(result.excess) == 0


def test_ambiguous_match_on_no_gpms():
    rpm = make_rpm()
    result = compute_delta(rpm, [])
    assert result.matched_by == MatchMethod.AMBIGUOUS
    assert result.requires_human_review is True
    assert result.patch_risk == "yellow"


def test_compute_all_deltas_one_per_role():
    rpm = make_rpm()
    gpms = [
        make_gpm(role_name="sample-lambda-role"),
        make_gpm(role_name="another-role"),
    ]
    results = compute_all_deltas(rpm, gpms)
    assert len(results) == 2


def test_resource_scope_violation_detected():
    rpm = make_rpm(calls=[
        SDKCall(
            service="s3", action="get_object", action_iam="s3:GetObject",
            resources=["arn:aws:s3:::my-bucket/*"],
            resources_wildcard=False, confidence=Confidence.HIGH
        )
    ])
    gpm = make_gpm(actions=["s3:GetObject"], resources=["*"])
    result = compute_delta(rpm, [gpm])
    resource_violations = [e for e in result.excess
                           if e.over_privilege_type == OverPrivilegeType.RESOURCE]
    assert len(resource_violations) >= 1
    assert resource_violations[0].action_iam == "s3:GetObject"