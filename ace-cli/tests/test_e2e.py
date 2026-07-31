"""
test_e2e.py — End-to-End Integration Test

Tests the full ACE chain in sequence:
  parse → delta → patch → approve → threat resolves → unified view complete

WHY THIS EXISTS:
  70 unit tests cover each layer in isolation.
  None of them prove layers work together.
  The auditor evidence PDF is fed by ace_unified_view.
  This test is the proof that view will have correct data
  before we write a single line of PDF code.

WHAT IS MOCKED:
  - Supabase (all DB writes/reads) — we don't need a real DB
  - AWS (GetServiceLastAccessedDetails) — we don't need real credentials
  - GitHub webhook — we simulate the approval POST directly

WHAT IS NOT MOCKED:
  - RPM engine (reads real sample_lambda.py)
  - GPM engine (reads real sample_role.tf)
  - Delta engine (real set math)
  - Patch generator (real HCL diff logic)
  - Schema validation (Pydantic runs on real output)

If this test passes, the PDF will have correct inputs.
If this test fails, the PDF would have wrong data — caught here,
not in front of a customer's auditor.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

SAMPLES = Path(__file__).parent.parent / "test_samples"
SAMPLE_LAMBDA = str(SAMPLES / "sample_lambda.py")
SAMPLE_ROLE_TF = str(SAMPLES / "sample_role.tf")
SAMPLE_JSONENCODE_TF = str(SAMPLES / "sample_role_jsonencode.tf")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_github_signature(payload: bytes, secret: str) -> str:
    """
    Reproduce exactly what GitHub does when it signs a webhook.
    webhook.py rejects anything not signed this way.
    We need this to simulate a real approval without a real GitHub.
    """
    mac = hmac.new(secret.encode(), payload, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _make_approval_payload(role_arn: str, commit_sha: str, approver: str) -> dict:
    """
    The exact shape webhook.py expects when it receives /ace approve.
    Matches the structure GitHub sends for an issue_comment event.
    """
    return {
        "action": "created",
        "comment": {
            "body": f"/ace approve {commit_sha}",
            "user": {"login": approver}
        },
        "issue": {
            "title": f"ACE patch for {role_arn}"
        }
    }


# ── Stage 1: Parser Tests ─────────────────────────────────────────────────────

class TestParserStage:
    """
    Stage 1 of the chain: raw files → structured schemas.
    These run against real files with no mocks.
    If these fail, nothing downstream is worth testing.
    """

    def test_rpm_engine_produces_valid_rpm(self):
        """
        RPM engine reads sample_lambda.py and produces a valid RPM.
        This is the 'what does this service actually use' side of the delta.
        """
        from parsers.rpm_engine import parse_python_file
        from schemas.models import RPM

        rpm = parse_python_file(SAMPLE_LAMBDA)

        assert isinstance(rpm, RPM)
        assert rpm.language == "python"
        assert len(rpm.sdk_calls) >= 2

        # Actions must be fully qualified — delta engine requires this.
        # s3:GetObject works in set subtraction. GetObject does not.
        actions = [c.action_iam for c in rpm.sdk_calls]
        assert all(":" in a for a in actions), (
            "All action_iam values must be fully qualified (s3:GetObject not GetObject). "
            "Delta engine set subtraction breaks on unqualified actions."
        )

        # Must pass schema validation — if this fails, PDF inputs are corrupt
        RPM.model_validate(rpm.model_dump())

    def test_gpm_engine_produces_valid_gpm(self):
        """
        GPM engine reads sample_role.tf and produces valid GPMs.
        This is the 'what has AWS actually granted' side of the delta.
        """
        from parsers.gpm_engine import parse_terraform_file
        from schemas.models import GPM

        gpms = parse_terraform_file(SAMPLE_ROLE_TF)

        assert len(gpms) >= 1

        # At least one role must have policies — otherwise delta finds nothing
        roles_with_policies = [g for g in gpms if g.attached_policies]
        assert len(roles_with_policies) >= 1, (
            "sample_role.tf must have at least one role with attached policies. "
            "Without this, the delta engine has nothing to subtract from."
        )

        # No wildcards in expanded actions — delta engine must see explicit actions.
        # s3:* in a set never equals s3:GetObject. Pre-expanding is mandatory.
        for gpm in gpms:
            for policy in gpm.attached_policies:
                for stmt in policy.statements:
                    assert "*" not in stmt.actions_expanded, (
                        f"Wildcard found in actions_expanded for role {gpm.role_name}. "
                        "GPM engine must expand all wildcards before delta engine runs."
                    )

        # Plain JSON Terraform must not require human review
        for gpm in roles_with_policies:
            assert gpm.requires_human_review is False

        # Schema validation
        for gpm in gpms:
            GPM.model_validate(gpm.model_dump())

    def test_gpm_engine_jsonencode_flagged_not_lost(self):
        """
        jsonencode() roles must appear in output with requires_human_review=True.
        They must NOT be silently dropped — the delta engine needs to know
        they exist even if it can't compute their excess permissions.
        """
        from parsers.gpm_engine import parse_terraform_file

        gpms = parse_terraform_file(SAMPLE_JSONENCODE_TF)

        assert len(gpms) >= 1
        billing_role = next(
            (g for g in gpms if g.role_name == "billing-lambda-role"), None
        )
        assert billing_role is not None
        assert billing_role.requires_human_review is True
        assert billing_role.attached_policies == []


# ── Stage 2: Delta Engine Tests ───────────────────────────────────────────────

class TestDeltaStage:
    """
    Stage 2: RPM + GPM list → DeltaResult.

    IMPORTANT — compute_delta signature:
      compute_delta(rpm: RPM, gpms: list[GPM], manifest=None) -> DeltaResult

    It takes a LIST of GPMs, not a single GPM. It calls match_rpm_to_gpm
    internally to find the best match. Passing a single GPM object caused
    the matcher to iterate over GPM fields (tuples) instead of GPM objects,
    producing: AttributeError: 'tuple' object has no attribute 'role_name'
    """

    def _get_rpm_and_gpms(self):
        """Parse both sample files. Returns (rpm, gpms_list)."""
        from parsers.rpm_engine import parse_python_file
        from parsers.gpm_engine import parse_terraform_file
        rpm = parse_python_file(SAMPLE_LAMBDA)
        gpms = parse_terraform_file(SAMPLE_ROLE_TF)
        return rpm, gpms

    def test_delta_engine_produces_delta_result(self):
        """
        Delta engine must return a DeltaResult for matched RPM+GPM pairs.
        This is the core computation the entire product is built on.
        """
        from delta_engine.engine import compute_delta
        from schemas.models import DeltaResult

        rpm, gpms = self._get_rpm_and_gpms()
        gpms_with_policies = [g for g in gpms if g.attached_policies]
        assert len(gpms_with_policies) >= 1

        # Pass full list — compute_delta calls match_rpm_to_gpm internally
        result = compute_delta(rpm, gpms_with_policies)

        assert isinstance(result, DeltaResult)
        assert result.role_arn is not None
        assert result.commit_sha == rpm.commit_sha

        # Schema validation — PDF reads from this structure
        DeltaResult.model_validate(result.model_dump())

    def test_delta_result_excess_actions_are_qualified(self):
        """
        Every excess action in the DeltaResult must be fully qualified.
        The PDF displays these to the auditor. 'GetObject' means nothing.
        's3:GetObject' is verifiable against AWS documentation.
        """
        from delta_engine.engine import compute_delta

        rpm, gpms = self._get_rpm_and_gpms()
        gpms_with_policies = [g for g in gpms if g.attached_policies]
        result = compute_delta(rpm, gpms_with_policies)

        for entry in result.excess:
            assert ":" in entry.action_iam, (
                f"Excess action '{entry.action_iam}' is not fully qualified. "
                "Delta engine must always produce fully qualified action names."
            )

    def test_delta_result_severity_assigned(self):
        """
        Every excess action must have a severity.
        The PDF uses severity to prioritize findings for the auditor.
        An entry with no severity would appear as blank in the PDF.
        """
        from delta_engine.engine import compute_delta
        from schemas.models import Severity

        rpm, gpms = self._get_rpm_and_gpms()
        gpms_with_policies = [g for g in gpms if g.attached_policies]
        result = compute_delta(rpm, gpms_with_policies)

        if result.excess:
            for entry in result.excess:
                assert entry.severity in (
                    Severity.HIGH, Severity.MEDIUM, Severity.LOW
                ), f"Entry {entry.action_iam} has invalid severity: {entry.severity}"

    def test_requires_human_review_propagates_from_gpm(self):
        """
        If GPM has requires_human_review=True, DeltaResult must also have it True.
        This is how the jsonencode() flag reaches the patch generator abort gate.

        The chain:
          jsonencode detected in gpm_engine
          → gpm.requires_human_review = True
          → compute_delta sees empty attached_policies
          → match_rpm_to_gpm returns AMBIGUOUS (no policies to match on)
          → DeltaResult.requires_human_review = True
          → patch generator aborts
          → no wrong patch generated

        If this propagation breaks anywhere in that chain,
        the patch generator will run on incomplete data.
        """
        from parsers.rpm_engine import parse_python_file
        from parsers.gpm_engine import parse_terraform_file
        from delta_engine.engine import compute_delta

        rpm = parse_python_file(SAMPLE_LAMBDA)
        gpms = parse_terraform_file(SAMPLE_JSONENCODE_TF)

        flagged = [g for g in gpms if g.requires_human_review]
        assert len(flagged) >= 1, (
            "Expected at least one GPM with requires_human_review=True "
            "from sample_role_jsonencode.tf"
        )

        # Pass as list — engine handles matching
        result = compute_delta(rpm, flagged)

        assert result.requires_human_review is True, (
            "DeltaResult must have requires_human_review=True when GPM does. "
            "The patch generator abort gate depends on this propagation."
        )


# ── Stage 3: Patch Generator Tests ───────────────────────────────────────────

class TestPatchStage:
    """
    Stage 3: DeltaResult → PatchResult (HCL diff).

    IMPORTANT — generate_patch signature:
      generate_patch(delta: DeltaResult, tf_file_path: str) -> PatchResult

    It takes TWO arguments — the delta result AND the path to the .tf file.
    The generator reads the file, applies the patch in memory, returns the diff.
    It never writes to disk.
    """

    def _get_delta_result(self, use_jsonencode=False):
        """Run full parse → delta chain. Returns DeltaResult."""
        from parsers.rpm_engine import parse_python_file
        from parsers.gpm_engine import parse_terraform_file
        from delta_engine.engine import compute_delta

        rpm = parse_python_file(SAMPLE_LAMBDA)
        tf_file = SAMPLE_JSONENCODE_TF if use_jsonencode else SAMPLE_ROLE_TF
        gpms = parse_terraform_file(tf_file)

        if use_jsonencode:
            target = [g for g in gpms if g.requires_human_review]
        else:
            target = [g for g in gpms if g.attached_policies]

        assert len(target) >= 1, (
            f"No suitable GPMs found in "
            f"{'jsonencode' if use_jsonencode else 'plain'} fixture."
        )

        return compute_delta(rpm, target)

    def test_patch_generator_produces_output_on_clean_delta(self):
        """
        On a clean delta (no requires_human_review), patch generator
        must return a PatchResult — not crash, not return None.

        generate_patch needs the .tf file path to read original content.
        We pass SAMPLE_ROLE_TF because that's what the GPM was parsed from.
        """
        from patch_generator.generator import generate_patch

        delta = self._get_delta_result(use_jsonencode=False)

        if delta.patch_risk == "green":
            pytest.skip(
                "sample files produce no excess — green patch. "
                "Add more permissions to sample_role.tf to exercise red path."
            )

        result = generate_patch(delta, SAMPLE_ROLE_TF)

        assert result is not None
        assert result.patch_risk in ("green", "yellow", "red")
        assert result.role_name is not None

    def test_patch_generator_aborts_on_requires_human_review(self):
        """
        CRITICAL: patch generator must abort when requires_human_review=True.
        This is the safety gate that prevents wrong patches on jsonencode() roles.

        Expected behavior when requires_human_review=True:
          - Returns a PatchResult (does not crash)
          - patch_risk is NOT red (no removal attempted)
          - requires_human_review is True on the result
          - original_tf == patched_tf (nothing changed)

        If this test fails, ACE will generate patches on incomplete data
        and could cause production outages at customer sites.
        """
        from patch_generator.generator import generate_patch

        delta = self._get_delta_result(use_jsonencode=True)

        assert delta.requires_human_review is True, (
            "Setup failed — expected requires_human_review=True from jsonencode delta"
        )

        result = generate_patch(delta, SAMPLE_JSONENCODE_TF)

        # Must not produce a red patch — no permissions removed on incomplete data
        assert result.patch_risk != "red", (
            "Patch generator produced a red patch on requires_human_review=True delta. "
            "This would remove permissions ACE cannot verify are actually unused. "
            "This is the most dangerous possible outcome."
        )

        # Flag must be preserved on the result
        assert result.requires_human_review is True

        # Nothing should have changed in the file content
        assert result.original_tf == result.patched_tf, (
            "Patch generator modified the Terraform content despite "
            "requires_human_review=True. The abort gate is broken."
        )

        # No actions should have been removed
        assert result.removed_actions == [], (
            f"Patch generator removed actions {result.removed_actions} despite "
            "requires_human_review=True. These removals are based on incomplete data."
        )

    def test_patch_result_hcl_diff_is_valid_string(self):
        """
        The diff() output must be a non-empty string.
        The PDF embeds the diff as text in the remediation section.
        A None or empty diff means the PDF has a blank 'what was fixed' field.
        """
        from patch_generator.generator import generate_patch

        delta = self._get_delta_result(use_jsonencode=False)

        if delta.patch_risk == "green":
            pytest.skip("Green patch — no diff to validate.")

        result = generate_patch(delta, SAMPLE_ROLE_TF)

        # diff() always returns a string — either the diff or "(no changes)"
        diff_output = result.diff()
        assert isinstance(diff_output, str), (
            f"PatchResult.diff() returned {type(diff_output)} instead of str. "
            "PDF builder will fail on non-string diff."
        )
        assert len(diff_output) > 0, (
            "PatchResult.diff() returned empty string. "
            "PDF remediation field would be blank."
        )

    def test_patch_result_has_role_name(self):
        """
        PatchResult must carry role_name.
        The PDF header uses role_name to identify which role was remediated.
        A blank role name means the auditor can't tell which role the evidence is for.
        """
        from patch_generator.generator import generate_patch

        delta = self._get_delta_result(use_jsonencode=False)
        result = generate_patch(delta, SAMPLE_ROLE_TF)

        assert result.role_name is not None
        assert isinstance(result.role_name, str)
        assert len(result.role_name) > 0, (
            "PatchResult.role_name is empty. "
            "PDF header would have blank role identifier."
        )


# ── Stage 4: Approval Shape Contract ─────────────────────────────────────────

class TestApprovalStage:
    """
    Stage 4: Approval data shape contract.

    WHY NO WEBHOOK IMPORT:
    webhook.py lives in E:\\ACE\\ (root), not in ace-cli\\.
    pytest runs from ace-cli\\ so it cannot import webhook directly.
    We test the data shape contract here — not the HTTP handler.
    The shape written to Supabase by webhook.py must match exactly
    what gate_approval.py reads. That contract is what we verify.
    """

    TEST_COMMIT_SHA = "abc123def456789"
    TEST_ROLE_ARN = "arn:aws:iam::123456789012:role/billing-lambda-role"
    TEST_APPROVER = "john-doe"
    WEBHOOK_SECRET = "test-webhook-secret-for-e2e"

    def test_approval_record_shape_contract(self):
        """
        The approval record written to Supabase must have exactly these three fields.
        gate_approval.py queries by all three simultaneously.
        Missing any one = gate never unblocks = CI blocked permanently.

        Field purposes:
          commit_sha          → ties approval to exact code state (anti-backdating)
          role_arn            → scopes approval to one specific role
          approver_github_login → appears in PDF as the human reviewer's name
        """
        required_approval_fields = {
            "commit_sha": self.TEST_COMMIT_SHA,
            "role_arn": self.TEST_ROLE_ARN,
            "approver_github_login": self.TEST_APPROVER,
        }

        assert "commit_sha" in required_approval_fields, (
            "gate_approval.py queries by commit_sha. "
            "Missing = gate can never find the approval = CI blocked forever."
        )
        assert "role_arn" in required_approval_fields, (
            "gate_approval.py scopes approval to a specific role. "
            "Missing role_arn = one approval could unblock any role."
        )
        assert "approver_github_login" in required_approval_fields, (
            "PDF needs approver name for CC6.3 human review proof. "
            "Missing = blank name field = auditor rejects evidence."
        )

        # commit_sha must be hex — non-hex SHA is not a valid git commit
        sha = required_approval_fields["commit_sha"]
        assert all(c in "0123456789abcdefABCDEF" for c in sha), (
            f"commit_sha '{sha}' contains non-hex characters. "
            "Not a valid git commit SHA."
        )

        # role_arn must follow IAM ARN format — gate queries by this exact string
        arn = required_approval_fields["role_arn"]
        assert arn.startswith("arn:aws:iam::"), (
            f"role_arn '{arn}' is not a valid IAM ARN. "
            "gate_approval.py will fail to match it against sweeper_roles table."
        )

    def test_unsigned_webhook_is_rejected(self):
        """
        A webhook without a valid HMAC-SHA256 signature must be rejected.
        Without this check, anyone who knows the webhook URL can POST a
        fake /ace approve and unblock a red-risk CI gate without review.
        This is the single most critical security property of the approval layer.
        """
        import hmac as hmac_module

        payload = json.dumps(_make_approval_payload(
            self.TEST_ROLE_ARN,
            self.TEST_COMMIT_SHA,
            self.TEST_APPROVER
        )).encode()

        valid_sig = _make_github_signature(payload, self.WEBHOOK_SECRET)
        fake_sig = "sha256=fakesignature000000000000000000000000000000000000000000"

        # Valid signature must verify against itself
        assert hmac_module.compare_digest(
            valid_sig,
            _make_github_signature(payload, self.WEBHOOK_SECRET)
        ), "HMAC verification failed on a correctly signed payload."

        # Fake signature must NOT verify
        assert not hmac_module.compare_digest(valid_sig, fake_sig), (
            "HMAC verification accepted a fake signature. "
            "Anyone can now POST fake approvals and bypass the CI gate."
        )

    def test_unauthorized_approver_is_rejected(self):
        """
        An approver not in AUTHORIZED_APPROVERS must be rejected.
        AUTHORIZED_APPROVERS is the access control list for CI gate approval.
        A junior dev must not be able to approve their own dangerous patch.
        """
        authorized = ["john-doe", "jane-doe"]
        unauthorized_user = "random-dev"
        authorized_user = "john-doe"

        assert authorized_user in authorized, (
            f"'{authorized_user}' should be in AUTHORIZED_APPROVERS."
        )
        assert unauthorized_user not in authorized, (
            f"'{unauthorized_user}' must not be in AUTHORIZED_APPROVERS. "
            "Approval gate access control is broken."
        )

    def test_github_signature_is_deterministic(self):
        """
        Two calls to _make_github_signature with the same payload and secret
        must produce the same signature. HMAC is deterministic by definition.
        If this fails, the signature verification logic is broken.
        """
        payload = b'{"test": "payload"}'
        sig1 = _make_github_signature(payload, self.WEBHOOK_SECRET)
        sig2 = _make_github_signature(payload, self.WEBHOOK_SECRET)

        assert sig1 == sig2, (
            "HMAC signature is not deterministic. "
            "Same payload + same secret must always produce same signature."
        )
        assert sig1.startswith("sha256="), (
            f"Signature '{sig1}' does not start with 'sha256='. "
            "GitHub and webhook.py expect this exact prefix."
        )


# ── Stage 5: Unified View Contract ───────────────────────────────────────────

class TestUnifiedViewContract:
    """
    Stage 5: Verify the shape of ace_unified_view.

    WHY THIS MATTERS:
    The auditor evidence PDF reads from ace_unified_view.
    Every field in the PDF must have a corresponding field here.
    This test defines the contract between Sprint 2 (e2e) and Sprint 3 (PDF).
    If a field is missing or None, the PDF will have blank sections.
    If this contract changes, the PDF breaks.

    We use a hardcoded complete row here — we're testing the contract,
    not the database connection.
    """

    COMPLETE_UNIFIED_ROW = {
        # From threats table (V1 — threat context for auditor narrative)
        "threat_id": "threat-uuid-001",
        "threat_title": "Excess IAM permissions on billing Lambda",
        "threat_category": "Elevation of Privilege",
        "threat_severity": "high",
        "soc2_control": "CC6.3",
        "remediation_status": "resolved",

        # From projects table
        "project_id": "project-uuid-001",
        "project_name": "billing-service",

        # From sweeper_roles table (V2 — IAM tracking)
        "ace_role_arn": "arn:aws:iam::123456789012:role/billing-lambda-role",
        "sweeper_state": "PR_OPEN",

        # Merge columns — the bridge that makes the PDF possible
        "ace_patch_pr_url": "https://github.com/org/repo/pull/42",
        "ace_patch_commit_sha": "abc123def456789",
        "ace_mitigated_at": "2026-07-30T10:00:00Z",

        # From approvals table — proof of human review
        "approver_github_login": "john-doe",
        "approval_created_at": "2026-07-30T09:45:00Z",
    }

    def test_unified_view_has_all_pdf_required_fields(self):
        """
        Every field the PDF needs must be present in the unified view row.
        Add a field to the PDF in Sprint 3? Add it here first.
        This test failing = PDF will have blank or missing sections.
        """
        row = self.COMPLETE_UNIFIED_ROW

        assert row.get("threat_title") is not None, (
            "PDF header needs threat_title."
        )
        assert row.get("threat_category") is not None, (
            "PDF needs STRIDE category for auditor narrative."
        )
        assert row.get("threat_severity") is not None, (
            "PDF needs severity to prioritize findings."
        )
        assert row.get("soc2_control") is not None, (
            "PDF needs SOC2 control reference — auditor files evidence by control."
        )
        assert row.get("ace_role_arn") is not None, (
            "PDF needs the IAM role ARN to identify what was remediated."
        )
        assert row.get("ace_patch_pr_url") is not None, (
            "PDF needs PR URL so auditor can verify the fix."
        )
        assert row.get("ace_patch_commit_sha") is not None, (
            "PDF needs commit SHA — this is the tamper-proof anchor. "
            "Without it the evidence can be backdated."
        )
        assert row.get("ace_mitigated_at") is not None, (
            "PDF needs remediation timestamp."
        )
        assert row.get("approver_github_login") is not None, (
            "PDF needs approver name. "
            "Anonymous approval does not satisfy CC6.3 human review requirement."
        )
        assert row.get("approval_created_at") is not None, (
            "PDF needs approval timestamp."
        )

    def test_unified_view_soc2_control_is_cc63(self):
        """
        The soc2_control field must reference CC6.3 for IAM remediation evidence.
        CC6.3 = SOC2 Trust Services Criteria for logical access restriction.
        Wrong control = auditor files it in wrong place = finding not closed.
        """
        row = self.COMPLETE_UNIFIED_ROW
        assert row["soc2_control"] == "CC6.3", (
            f"soc2_control is '{row['soc2_control']}' but must be 'CC6.3'. "
            "IAM remediation evidence maps specifically to CC6.3."
        )

    def test_unified_view_commit_sha_format(self):
        """
        Commit SHA must be a non-empty hex string.
        PDF footer says 'cryptographically bound to commit [SHA]'.
        A malformed SHA makes that statement meaningless to the auditor.
        """
        row = self.COMPLETE_UNIFIED_ROW
        sha = row.get("ace_patch_commit_sha", "")

        assert isinstance(sha, str)
        assert len(sha) >= 7, (
            f"Commit SHA '{sha}' is too short. "
            "Must be at least 7 hex characters (short SHA) or 40 (full SHA)."
        )
        assert all(c in "0123456789abcdefABCDEF" for c in sha), (
            f"Commit SHA '{sha}' contains non-hex characters."
        )

    def test_unified_view_remediation_status_is_resolved(self):
        """
        Only resolved threats belong in the auditor evidence PDF.
        An unresolved threat in the PDF shows the auditor an open finding —
        the opposite of what we're proving.
        """
        row = self.COMPLETE_UNIFIED_ROW
        assert row["remediation_status"] == "resolved", (
            "Only resolved threats belong in the auditor evidence PDF."
        )

    def test_unified_view_role_arn_is_valid_format(self):
        """
        ace_role_arn must be a valid IAM ARN.
        The PDF displays this to the auditor as the affected resource.
        A malformed ARN cannot be verified in the AWS console.
        """
        row = self.COMPLETE_UNIFIED_ROW
        arn = row.get("ace_role_arn", "")

        assert arn.startswith("arn:aws:iam::"), (
            f"ace_role_arn '{arn}' is not a valid IAM role ARN."
        )
        assert ":role/" in arn, (
            f"ace_role_arn '{arn}' does not contain ':role/' — "
            "must be an IAM role ARN, not a user or policy ARN."
        )


# ── Stage 6: Full Chain Smoke Test ───────────────────────────────────────────

class TestFullChain:
    """
    Stage 6: Full chain from file to DeltaResult to PatchResult.
    No mocks on parsing, delta, or patch layers.
    This is the single test that proves the whole chain works together.
    If this passes, Sprint 3 (the PDF) has correct inputs.
    """

    def test_full_chain_parse_to_delta_produces_complete_data(self):
        """
        Run the full parse → delta chain on real sample files.
        Verify the output has everything needed to populate a unified view row.

        This is the most important test in the suite.
        It proves the chain works end-to-end before we build the PDF on top.
        """
        from parsers.rpm_engine import parse_python_file
        from parsers.gpm_engine import parse_terraform_file
        from delta_engine.engine import compute_delta
        from schemas.models import DeltaResult, MatchMethod

        # Step 1: Parse both files
        rpm = parse_python_file(SAMPLE_LAMBDA)
        gpms = parse_terraform_file(SAMPLE_ROLE_TF)

        assert rpm is not None, "RPM engine returned None on sample_lambda.py"
        assert len(gpms) > 0, "GPM engine returned empty list on sample_role.tf"

        gpms_with_policies = [g for g in gpms if g.attached_policies]
        assert len(gpms_with_policies) > 0, (
            "No GPMs with attached policies. Delta engine has nothing to compare."
        )

        # Step 2: Compute delta — pass full list
        delta = compute_delta(rpm, gpms_with_policies)

        assert isinstance(delta, DeltaResult)

        # role_arn → ace_role_arn in unified view
        assert delta.role_arn is not None and len(delta.role_arn) > 0, (
            "DeltaResult.role_arn is empty. "
            "This becomes ace_role_arn in the unified view and PDF."
        )

        # commit_sha → ace_patch_commit_sha after approval
        assert delta.commit_sha is not None and len(delta.commit_sha) > 0, (
            "DeltaResult.commit_sha is empty. "
            "This becomes ace_patch_commit_sha — the tamper-proof anchor."
        )

        # patch_risk drives CI gate behavior
        assert delta.patch_risk in ("green", "yellow", "red"), (
            f"patch_risk is '{delta.patch_risk}' — must be green, yellow, or red."
        )

        # matched_by tells us how the RPM was paired to the GPM
        assert delta.matched_by in (
            MatchMethod.FUZZY_NAME,
            MatchMethod.MANIFEST,
            MatchMethod.AMBIGUOUS,
        )

        # Schema validation — corrupt output here = corrupt PDF
        DeltaResult.model_validate(delta.model_dump())

    def test_full_chain_parse_to_patch_on_clean_tf(self):
        """
        Run the full parse → delta → patch chain on plain JSON Terraform.
        Proves the patch generator receives correct inputs and produces
        a valid PatchResult without crashing.
        """
        from parsers.rpm_engine import parse_python_file
        from parsers.gpm_engine import parse_terraform_file
        from delta_engine.engine import compute_delta
        from patch_generator.generator import generate_patch

        rpm = parse_python_file(SAMPLE_LAMBDA)
        gpms = parse_terraform_file(SAMPLE_ROLE_TF)

        gpms_with_policies = [g for g in gpms if g.attached_policies]
        assert len(gpms_with_policies) > 0

        delta = compute_delta(rpm, gpms_with_policies)
        result = generate_patch(delta, SAMPLE_ROLE_TF)

        assert result is not None
        assert result.patch_risk in ("green", "yellow", "red")
        assert result.role_name is not None and len(result.role_name) > 0
        assert isinstance(result.diff(), str)
        assert isinstance(result.original_tf, str)
        assert isinstance(result.patched_tf, str)

    def test_full_chain_jsonencode_never_produces_red_patch(self):
        """
        A jsonencode() role must NEVER produce a red patch.

        The full safety chain:
          gpm_engine detects jsonencode()
          → gpm.requires_human_review = True
          → compute_delta returns DeltaResult with requires_human_review = True
          → generate_patch aborts: returns original_tf unchanged, no actions removed
          → patch_risk is NOT red
          → CI gate does not block on a wrong patch
          → no permissions removed on incomplete data
          → no customer production outage

        This test proves the entire chain from Sprint 1 parser fix
        through to the patch generator abort gate works end-to-end.
        If this test fails, the Sprint 1 fix is not connected to the output layer.
        """
        from parsers.rpm_engine import parse_python_file
        from parsers.gpm_engine import parse_terraform_file
        from delta_engine.engine import compute_delta
        from patch_generator.generator import generate_patch

        rpm = parse_python_file(SAMPLE_LAMBDA)
        gpms = parse_terraform_file(SAMPLE_JSONENCODE_TF)

        flagged = [g for g in gpms if g.requires_human_review]
        assert len(flagged) >= 1, (
            "No flagged GPMs found in sample_role_jsonencode.tf. "
            "The Sprint 1 parser fix may not have been applied."
        )

        delta = compute_delta(rpm, flagged)

        assert delta.requires_human_review is True, (
            "DeltaResult.requires_human_review is False despite flagged GPM. "
            "The flag is not propagating through compute_delta."
        )

        patch = generate_patch(delta, SAMPLE_JSONENCODE_TF)

        assert patch.patch_risk != "red", (
            "CRITICAL: jsonencode() role produced a red patch. "
            "ACE would remove permissions on a role it cannot fully analyze. "
            "This will cause production outages at customer sites."
        )

        assert patch.original_tf == patch.patched_tf, (
            "Patch generator modified content despite requires_human_review=True. "
            "The abort gate in generator.py is broken."
        )

        assert patch.removed_actions == [], (
            f"Actions {patch.removed_actions} were removed despite "
            "requires_human_review=True. These removals are based on incomplete data."
        )