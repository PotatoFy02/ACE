"""
GPM Engine — Granted Permissions Manifest extractor.
Reads Terraform .tf files, finds IAM role policies,
outputs valid GPM objects that pass GPM.model_validate().

hcl2 wraps ALL resource type keys, resource name keys, and string
values in extra quotes. Every lookup strips them via _unquote().

jsonencode() / heredoc / ${} interpolation: hcl2 returns these as
raw unparseable strings. _parse_policy_doc() detects them and returns
requires_human_review=True. The role is still returned — never silently
skipped. Patch generator aborts on requires_human_review=True.
"""

import json
import logging
import re
import subprocess
from pathlib import Path

import hcl2

from schemas.models import GPM, AttachedPolicy, Statement

# NEW: logger so fallback triggers are visible in CI output
logger = logging.getLogger(__name__)


WILDCARD_EXPANSIONS: dict[str, list[str]] = {
    "s3:*": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
        "s3:ListBucket", "s3:CreateBucket", "s3:DeleteBucket",
        "s3:CopyObject", "s3:GetBucketPolicy", "s3:PutBucketPolicy",
    ],
    "dynamodb:*": [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
        "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan",
        "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem",
        "dynamodb:CreateTable", "dynamodb:DeleteTable",
    ],
    "lambda:*": [
        "lambda:InvokeFunction", "lambda:CreateFunction",
        "lambda:DeleteFunction", "lambda:UpdateFunctionCode",
        "lambda:GetFunction", "lambda:ListFunctions",
    ],
    "iam:*": [
        "iam:CreateRole", "iam:DeleteRole", "iam:GetRole",
        "iam:AttachRolePolicy", "iam:DetachRolePolicy",
        "iam:CreatePolicy", "iam:DeletePolicy",
        "iam:CreateUser", "iam:DeleteUser", "iam:CreateAccessKey",
    ],
    "kms:*": [
        "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey",
        "kms:DescribeKey", "kms:CreateKey", "kms:Sign", "kms:Verify",
    ],
    "*": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:DeleteBucket",
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
        "lambda:InvokeFunction", "lambda:DeleteFunction",
        "iam:CreateRole", "iam:DeleteRole", "iam:CreateAccessKey",
        "kms:Decrypt", "kms:Encrypt", "sts:AssumeRole",
    ],
}


def _unquote(s: str) -> str:
    """
    hcl2 wraps keys and string values in extra double-quotes.
    '"aws_iam_role"' -> 'aws_iam_role'
    '"my-lambda-role"' -> 'my-lambda-role'
    Also strips surrounding whitespace.
    """
    if isinstance(s, str):
        s = s.strip()
        if s.startswith('"') and s.endswith('"') and len(s) >= 2:
            return s[1:-1]
    return s


def _unquote_policy_string(s: str) -> str:
    """
    Policy strings come double-escaped from hcl2.
    Outer quotes stripped by _unquote(), then internal \\\" -> \"
    so json.loads() can parse them.
    """
    s = _unquote(s)
    s = s.replace('\\"', '"')
    return s


def _expand_actions(actions: list[str]) -> tuple[list[str], bool]:
    has_wildcard = False
    expanded = []
    for action in actions:
        if "*" in action:
            has_wildcard = True
            expanded.extend(WILDCARD_EXPANSIONS.get(action, [action]))
        else:
            expanded.append(action)
    return (list(set(expanded)), has_wildcard)


def _get_git_author(file_path: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ae", file_path],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or None
    except Exception:
        return None


# CHANGED: now returns tuple[list[Statement], bool]
# Second element is requires_human_review.
# Previously returned list[Statement] and silently returned []
# on jsonencode() — that was the bug.
def _parse_policy_doc(policy_value, role_name: str = "") -> tuple[list[Statement], bool]:
    """
    Parse a policy value (string or dict) into Statement objects.

    Returns (statements, requires_human_review).

    requires_human_review=True when:
    - policy uses jsonencode() — hcl2 returns it as a raw unparseable string
    - policy uses ${} variable interpolation
    - policy is a string but not valid JSON after unquoting
    - policy value is an unexpected type

    Never crashes. Never returns None. Always returns a tuple.
    The role is always returned by the caller — never silently dropped.
    """
    if isinstance(policy_value, str):
        raw = _unquote(policy_value)

        # NEW: detect jsonencode() — hcl2 can't evaluate HCL functions,
        # so it returns the literal string "jsonencode({...})".
        # json.loads would raise JSONDecodeError — we detect it first
        # and flag for human review instead of silently returning [].
        if "jsonencode" in raw:
            logger.warning(
                f"Role '{role_name}': policy uses jsonencode() — "
                f"cannot parse statically. Flagging requires_human_review=True. "
                f"Open a PR manually with the correct least-privilege policy."
            )
            return [], True

        # NEW: detect ${} variable interpolation — same problem as jsonencode,
        # hcl2 can't resolve variables at parse time.
        if "${" in raw:
            logger.warning(
                f"Role '{role_name}': policy uses variable interpolation (${{...}}) — "
                f"cannot resolve statically. Flagging requires_human_review=True."
            )
            return [], True

        # Supported path: plain JSON string
        policy_str = _unquote_policy_string(policy_value)
        try:
            policy_doc = json.loads(policy_str)
        except json.JSONDecodeError:
            # CHANGED: was silently returning []. Now flags human review
            # so the role isn't lost — it appears in output with a warning.
            logger.warning(
                f"Role '{role_name}': policy is a string but not valid JSON "
                f"after unquoting. Flagging requires_human_review=True."
            )
            return [], True

    elif isinstance(policy_value, dict):
        # hcl2 parsed it into a dict cleanly — the happy path
        policy_doc = policy_value

    else:
        # NEW: unknown type guard — never crash on unexpected hcl2 output
        logger.warning(
            f"Role '{role_name}': policy value is unexpected type "
            f"{type(policy_value).__name__}. Flagging requires_human_review=True."
        )
        return [], True

    # Build Statement objects from the parsed policy doc
    statements = []
    for stmt in policy_doc.get("Statement", []):
        raw_actions = stmt.get("Action", [])
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]

        raw_resources = stmt.get("Resource", ["*"])
        if isinstance(raw_resources, str):
            raw_resources = [raw_resources]

        expanded, has_wildcard = _expand_actions(raw_actions)
        resources_wildcard = "*" in raw_resources

        effect = stmt.get("Effect", "Allow")
        if effect not in ("Allow", "Deny"):
            effect = "Allow"

        statements.append(Statement(
            effect=effect,
            actions=raw_actions,
            actions_expanded=expanded,
            actions_wildcard=has_wildcard,
            resources=raw_resources,
            resources_wildcard=resources_wildcard,
        ))

    return statements, False  # parsed cleanly — no human review needed


def parse_terraform_file(file_path: str, repo_path: str = ".") -> list[GPM]:
    path = Path(file_path)
    gpms: list[GPM] = []
    role_map: dict[str, GPM] = {}

    with open(path, "r", encoding="utf-8") as f:
        tf_data = hcl2.load(f)

    resources = tf_data.get("resource", [])

    # Pass 1 — collect all aws_iam_role resources (unchanged)
    for resource_block in resources:
        for raw_type_key, type_val in resource_block.items():
            if _unquote(raw_type_key) != "aws_iam_role":
                continue
            for raw_role_key, role_config in type_val.items():
                role_key = _unquote(raw_role_key)
                if isinstance(role_config, list):
                    role_config = role_config[0]
                actual_name = _unquote(role_config.get("name", role_key))

                gpm = GPM(
                    role_name=actual_name,
                    role_arn=f"arn:aws:iam::${{aws_account_id}}:role/{actual_name}",
                    created_by=_get_git_author(file_path),
                    last_modified_pr=None,
                    attached_policies=[],
                    requires_human_review=False,   # NEW: explicit default
                )
                gpms.append(gpm)
                role_map[role_key] = gpm

    # Pass 2 — attach inline policies
    # CHANGED: _parse_policy_doc now returns (statements, needs_review)
    # instead of just statements. Roles with unparseable policies are
    # flagged requires_human_review=True instead of silently dropped.
    for resource_block in resources:
        for raw_type_key, type_val in resource_block.items():
            if _unquote(raw_type_key) != "aws_iam_role_policy":
                continue
            for raw_policy_key, policy_config in type_val.items():
                policy_key = _unquote(raw_policy_key)
                if isinstance(policy_config, list):
                    policy_config = policy_config[0]

                policy_value = policy_config.get("policy")
                if not policy_value:
                    continue

                # Find which role this policy belongs to first,
                # so we can pass role_name to _parse_policy_doc for logging
                raw_role_ref = _unquote(str(policy_config.get("role", "")))
                target_gpm: GPM | None = None
                for tf_key, gpm in role_map.items():
                    if tf_key == raw_role_ref or gpm.role_name == raw_role_ref:
                        target_gpm = gpm
                        break
                if target_gpm is None and gpms:
                    target_gpm = gpms[0]

                role_name_for_log = target_gpm.role_name if target_gpm else policy_key

                # CHANGED: unpack tuple instead of bare list
                statements, needs_review = _parse_policy_doc(
                    policy_value,
                    role_name=role_name_for_log
                )

                # NEW: if unparseable, flag the role and move on.
                # Previously this was `if not statements: continue`
                # which silently dropped the role from output entirely.
                if needs_review:
                    if target_gpm is not None:
                        # Use object.__setattr__ in case model becomes frozen later
                        target_gpm.requires_human_review = True
                    continue

                if not statements:
                    continue

                attached = AttachedPolicy(
                    policy_arn=f"arn:aws:iam::local:policy/{policy_key}",
                    statements=statements
                )

                if target_gpm is not None:
                    target_gpm.attached_policies.append(attached)

    # Validate all GPMs before returning
    for gpm in gpms:
        GPM.model_validate(gpm.model_dump())

    return gpms