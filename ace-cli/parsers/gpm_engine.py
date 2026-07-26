"""
GPM Engine — Granted Permissions Manifest extractor.
Reads Terraform .tf files, finds IAM role policies,
outputs valid GPM objects that pass GPM.model_validate().

hcl2 wraps ALL resource type keys, resource name keys, and string
values in extra quotes. Every lookup strips them via _unquote().
"""

import json
import re
import subprocess
from pathlib import Path

import hcl2

from schemas.models import GPM, AttachedPolicy, Statement


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
    Outer quotes stripped by _unquote(), then inner \\\" -> \"
    so json.loads() can parse them.
    """
    s = _unquote(s)
    # Unescape internal escaped quotes
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


def _parse_policy_doc(policy_value) -> list[Statement]:
    """Parse a policy value (string or dict) into Statement objects."""
    if isinstance(policy_value, str):
        policy_str = _unquote_policy_string(policy_value)
        try:
            policy_doc = json.loads(policy_str)
        except json.JSONDecodeError:
            return []
    elif isinstance(policy_value, dict):
        policy_doc = policy_value
    else:
        return []

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

    return statements


def parse_terraform_file(file_path: str, repo_path: str = ".") -> list[GPM]:
    path = Path(file_path)
    gpms: list[GPM] = []
    # Maps bare tf resource key (e.g. "lambda_role") -> GPM
    role_map: dict[str, GPM] = {}

    with open(path, "r", encoding="utf-8") as f:
        tf_data = hcl2.load(f)

    resources = tf_data.get("resource", [])

    # Pass 1 — collect all aws_iam_role resources
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
                    attached_policies=[]
                )
                gpms.append(gpm)
                role_map[role_key] = gpm

    # Pass 2 — attach inline policies
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

                statements = _parse_policy_doc(policy_value)
                if not statements:
                    continue

                attached = AttachedPolicy(
                    policy_arn=f"arn:aws:iam::local:policy/{policy_key}",
                    statements=statements
                )

                # role field is also quoted by hcl2: '"lambda_role"' -> 'lambda_role'
                raw_role_ref = _unquote(str(policy_config.get("role", "")))

                matched = False
                for tf_key, gpm in role_map.items():
                    if tf_key == raw_role_ref or gpm.role_name == raw_role_ref:
                        gpm.attached_policies.append(attached)
                        matched = True
                        break

                if not matched and gpms:
                    gpms[0].attached_policies.append(attached)

    for gpm in gpms:
        GPM.model_validate(gpm.model_dump())

    return gpms