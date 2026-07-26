from pathlib import Path
from schemas.models import RPM, GPM

SAMPLES = Path(__file__).parent.parent / "test_samples"


def test_rpm_engine_parses_sample_lambda():
    from parsers.rpm_engine import parse_python_file
    rpm = parse_python_file(str(SAMPLES / "sample_lambda.py"))

    assert isinstance(rpm, RPM)
    assert rpm.language == "python"
    assert len(rpm.sdk_calls) >= 2

    actions = [c.action_iam for c in rpm.sdk_calls]
    assert "s3:GetObject" in actions
    assert "dynamodb:PutItem" in actions


def test_rpm_engine_confidence_levels():
    from parsers.rpm_engine import parse_python_file
    rpm = parse_python_file(str(SAMPLES / "sample_lambda.py"))

    s3_call = next(c for c in rpm.sdk_calls if c.action_iam == "s3:GetObject")
    dynamo_call = next(c for c in rpm.sdk_calls if c.action_iam == "dynamodb:PutItem")

    assert s3_call.confidence == "high"     # hardcoded bucket name
    assert dynamo_call.confidence == "medium"  # env var resource


def test_rpm_output_passes_schema():
    from parsers.rpm_engine import parse_python_file
    rpm = parse_python_file(str(SAMPLES / "sample_lambda.py"))
    RPM.model_validate(rpm.model_dump())    # must not raise


def test_gpm_engine_parses_sample_tf():
    from parsers.gpm_engine import parse_terraform_file
    gpms = parse_terraform_file(str(SAMPLES / "sample_role.tf"))

    assert len(gpms) >= 1
    gpm = gpms[0]
    assert isinstance(gpm, GPM)


def test_gpm_wildcard_is_expanded():
    from parsers.gpm_engine import parse_terraform_file
    gpms = parse_terraform_file(str(SAMPLES / "sample_role.tf"))

    all_statements = [
        stmt
        for gpm in gpms
        for policy in gpm.attached_policies
        for stmt in policy.statements
    ]

    wildcard_stmt = next((s for s in all_statements if s.actions_wildcard), None)
    assert wildcard_stmt is not None
    assert "s3:*" not in wildcard_stmt.actions_expanded
    assert "s3:GetObject" in wildcard_stmt.actions_expanded


def test_gpm_output_passes_schema():
    from parsers.gpm_engine import parse_terraform_file
    gpms = parse_terraform_file(str(SAMPLES / "sample_role.tf"))
    for gpm in gpms:
        GPM.model_validate(gpm.model_dump())    # must not raise