from pathlib import Path
from schemas.models import (
    DeltaResult, DeltaEntry, OverPrivilegeType,
    Severity, Confidence, MatchMethod
)
from patch_generator.generator import generate_patch, PatchResult

SAMPLE_TF = Path(__file__).parent.parent / "test_samples" / "sample_role.tf"


def make_delta(excess_actions: list[str], patch_risk: str = "red") -> DeltaResult:
    entries = [
        DeltaEntry(
            action_iam=a,
            over_privilege_type=OverPrivilegeType.ACTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            reason=f"{a} is excess"
        )
        for a in excess_actions
    ]
    return DeltaResult(
        role_arn="arn:aws:iam::123:role/my-lambda-role",
        role_name="my-lambda-role",
        commit_sha="abc123",
        matched_by=MatchMethod.FUZZY_NAME,
        rpm_service_name="sample_lambda",
        excess=entries,
        requires_human_review=False,
        patch_risk=patch_risk,
    )


def test_patch_removes_excess_actions():
    # s3:DeleteBucket and s3:PutObject are excess
    # sample_role.tf has s3:* wildcard — patch generator must expand then remove
    delta = make_delta(["s3:DeleteBucket", "s3:PutObject"])
    result = generate_patch(delta, str(SAMPLE_TF))
    assert isinstance(result, PatchResult)
    assert result.changed is True
    assert "s3:DeleteBucket" in result.removed_actions
    assert "s3:PutObject" in result.removed_actions
    # Wildcard must be gone — replaced with explicit list
    assert "s3:*" not in result.patched_tf
    # Required actions must still be present
    assert "s3:GetObject" in result.patched_tf


def test_patch_no_excess_returns_unchanged():
    delta = make_delta([], patch_risk="green")
    result = generate_patch(delta, str(SAMPLE_TF))
    assert result.changed is False
    assert result.removed_actions == []


def test_patch_result_has_summary():
    delta = make_delta(["dynamodb:GetItem"])
    result = generate_patch(delta, str(SAMPLE_TF))
    summary = result.summary()
    assert "my-lambda-role" in summary
    assert "dynamodb:GetItem" in summary


def test_patch_result_has_diff():
    delta = make_delta(["dynamodb:GetItem"])
    result = generate_patch(delta, str(SAMPLE_TF))
    diff = result.diff()
    assert isinstance(diff, str)
    assert len(diff) > 0


def test_patch_preserves_required_actions():
    delta = make_delta(["dynamodb:GetItem"])
    result = generate_patch(delta, str(SAMPLE_TF))
    assert "dynamodb:PutItem" in result.patched_tf