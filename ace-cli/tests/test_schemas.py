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