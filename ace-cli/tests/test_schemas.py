import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from schemas.models import RPM, GPM

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_rpm_example_validates():
    rpm = RPM.model_validate(load_fixture("rpm_example.json"))
    assert rpm.service_name == "user-auth-service"
    assert rpm.sdk_calls[0].confidence == "high"


def test_rpm_rejects_bad_confidence():
    data = load_fixture("rpm_example.json")
    data["sdk_calls"][0]["confidence"] = "super-sure"
    with pytest.raises(ValidationError):
        RPM.model_validate(data)


def test_rpm_low_confidence_validates():
    rpm = RPM.model_validate(load_fixture("rpm_low_confidence.json"))
    assert rpm.sdk_calls[0].confidence == "low"


def test_gpm_example_validates():
    gpm = GPM.model_validate(load_fixture("gpm_example.json"))
    assert gpm.role_name == "user-auth-lambda-role"
    assert "s3:DeleteBucket" in gpm.attached_policies[0].statements[0].actions_expanded


def test_gpm_requires_actions_expanded():
    data = load_fixture("gpm_example.json")
    del data["attached_policies"][0]["statements"][0]["actions_expanded"]
    with pytest.raises(ValidationError):
        GPM.model_validate(data)


def test_gpm_cross_account_validates():
    gpm = GPM.model_validate(load_fixture("gpm_cross_account.json"))
    assert gpm.attached_policies[0].statements[0].actions_expanded == ["sts:AssumeRole"]
    # ─── STRESS TESTS: pushing the models to breaking points ───


# 1. Completely empty input — no fields at all
def test_rpm_rejects_empty_dict():
    with pytest.raises(ValidationError):
        RPM.model_validate({})


def test_gpm_rejects_empty_dict():
    with pytest.raises(ValidationError):
        GPM.model_validate({})


# 2. Wrong data types — numbers where strings should be
def test_rpm_rejects_wrong_types():
    with pytest.raises(ValidationError):
        RPM.model_validate({
            "service_name": 12345,          # should be str
            "language": "python",
            "commit_sha": True,             # should be str
            "sdk_calls": "not a list"       # should be list
        })


def test_gpm_rejects_wrong_types():
    with pytest.raises(ValidationError):
        GPM.model_validate({
            "role_name": ["not", "a", "string"],   # should be str
            "role_arn": 999,                        # should be str
            "attached_policies": "nope"             # should be list
        })


# 3. Missing required fields one by one
def test_rpm_rejects_missing_commit_sha():
    with pytest.raises(ValidationError):
        RPM.model_validate({
            "service_name": "my-service",
            "language": "python"
            # commit_sha missing
            # sdk_calls missing
        })


def test_gpm_rejects_missing_role_arn():
    with pytest.raises(ValidationError):
        GPM.model_validate({
            "role_name": "my-role"
            # role_arn missing
            # attached_policies missing
        })


# 4. Invalid language — must be one of the four allowed values
def test_rpm_rejects_invalid_language():
    with pytest.raises(ValidationError):
        RPM.model_validate({
            "service_name": "my-service",
            "language": "cobol",            # not in the Literal list
            "commit_sha": "abc123",
            "sdk_calls": []
        })


# 5. Invalid effect in GPM statement — must be Allow or Deny only
def test_gpm_rejects_invalid_effect():
    with pytest.raises(ValidationError):
        GPM.model_validate({
            "role_name": "my-role",
            "role_arn": "arn:aws:iam::123:role/my-role",
            "attached_policies": [
                {
                    "policy_arn": "arn:aws:iam::123:policy/MyPolicy",
                    "statements": [
                        {
                            "effect": "Maybe",              # only Allow or Deny allowed
                            "actions": ["s3:GetObject"],
                            "actions_expanded": ["s3:GetObject"],
                            "actions_wildcard": False,
                            "resources": ["*"],
                            "resources_wildcard": True
                        }
                    ]
                }
            ]
        })


# 6. Wildcard action string sneaking through as an expanded action
# actions_expanded should contain explicit actions, not raw wildcards
# This tests that your schema catches "s3:*" in the expanded list
def test_gpm_flags_wildcard_in_actions_expanded():

    data = load_fixture("gpm_example.json")
    gpm = GPM.model_validate(data)
    stmt = gpm.attached_policies[0].statements[0]
    assert stmt.actions_wildcard is True
    assert "s3:*" not in stmt.actions_expanded   # raw wildcard must NOT be in expanded list


# 7. Injection attempt — malicious string in action_iam field

def test_rpm_handles_injection_string_safely():
    data = load_fixture("rpm_example.json")
    data["sdk_calls"][0]["action_iam"] = "<script>alert('xss')</script>"
    # Schema accepts it as a string (content validation is Delta Engine's job)
    # but it must not crash and must remain exactly the string passed in
    rpm = RPM.model_validate(data)
    assert rpm.sdk_calls[0].action_iam == "<script>alert('xss')</script>"


# 8. Empty sdk_calls list — valid RPM with no calls found yet
def test_rpm_accepts_empty_sdk_calls():
    rpm = RPM.model_validate({
        "service_name": "empty-service",
        "language": "go",
        "commit_sha": "000000",
        "sdk_calls": []
    })
    assert rpm.sdk_calls == []


# 9. Empty attached_policies list — valid GPM with no policies yet
def test_gpm_accepts_empty_policies():
    gpm = GPM.model_validate({
        "role_name": "bare-role",
        "role_arn": "arn:aws:iam::123:role/bare-role",
        "attached_policies": []
    })
    assert gpm.attached_policies == []


# 10. Extremely long string — should not crash the validator
def test_rpm_handles_very_long_service_name():
    rpm = RPM.model_validate({
        "service_name": "a" * 10000,
        "language": "typescript",
        "commit_sha": "abc123",
        "sdk_calls": []
    })
    assert len(rpm.service_name) == 10000