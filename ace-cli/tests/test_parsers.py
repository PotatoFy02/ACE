from pathlib import Path
from schemas.models import RPM, GPM

SAMPLES = Path(__file__).parent.parent / "test_samples"


# ── Original 6 tests (unchanged) ─────────────────────────────────────────────

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

    assert s3_call.confidence == "high"       # hardcoded bucket name
    assert dynamo_call.confidence == "medium"  # env var resource


def test_rpm_output_passes_schema():
    from parsers.rpm_engine import parse_python_file
    rpm = parse_python_file(str(SAMPLES / "sample_lambda.py"))
    RPM.model_validate(rpm.model_dump())      # must not raise


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
        GPM.model_validate(gpm.model_dump())  # must not raise


# ── New tests: jsonencode() fallback ─────────────────────────────────────────

def test_gpm_engine_jsonencode_does_not_crash():
    """
    jsonencode() policies must never crash or silently return empty list.
    The role must still appear in output with requires_human_review=True.
    """
    from parsers.gpm_engine import parse_terraform_file
    gpms = parse_terraform_file(str(SAMPLES / "sample_role_jsonencode.tf"))

    # Must return the role — not an empty list
    assert len(gpms) >= 1

    # Role name must be identified even though policy can't be parsed
    role_names = [gpm.role_name for gpm in gpms]
    assert "billing-lambda-role" in role_names

    # The role must be flagged — patch generator will abort on this
    billing_role = next(g for g in gpms if g.role_name == "billing-lambda-role")
    assert billing_role.requires_human_review is True

    # attached_policies must be empty list — not None, not a crash
    assert billing_role.attached_policies == []


def test_gpm_engine_jsonencode_passes_schema():
    """
    Even with requires_human_review=True the GPM must pass schema validation.
    The new field must be in the model and serialize cleanly.
    """
    from parsers.gpm_engine import parse_terraform_file
    gpms = parse_terraform_file(str(SAMPLES / "sample_role_jsonencode.tf"))

    for gpm in gpms:
        GPM.model_validate(gpm.model_dump())  # must not raise


def test_gpm_engine_plain_json_unaffected_by_fallback():
    """
    Regression guard: the jsonencode fix must not break plain JSON policies.
    sample_role.tf must still parse correctly with requires_human_review=False.
    """
    from parsers.gpm_engine import parse_terraform_file
    gpms = parse_terraform_file(str(SAMPLES / "sample_role.tf"))

    assert len(gpms) >= 1

    # At least one role must have attached policies with actual statements
    roles_with_policies = [g for g in gpms if g.attached_policies]
    assert len(roles_with_policies) >= 1

    # Plain JSON roles must NOT be flagged for human review
    for gpm in roles_with_policies:
        assert gpm.requires_human_review is False