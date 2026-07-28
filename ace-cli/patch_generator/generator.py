"""
Patch Generator — converts DeltaResult into a minimal HCL policy patch.

Input:  DeltaResult + original .tf file content
Output: Modified .tf content with excess permissions removed

Rules:
- Wildcards (s3:*) are expanded before patching — output is always explicit
- Never removes a permission that is required by the RPM
- Red-risk patches flagged — never auto-applied
- Output is a suggested patch, not an applied change
- ABORTS if requires_human_review=True — blind spots mean patch is unsafe
"""

import json
import re
from pathlib import Path
from schemas.models import DeltaResult, OverPrivilegeType


WILDCARD_EXPANSIONS: dict[str, list[str]] = {
    "*": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:DeleteBucket",
        "s3:ListBucket", "s3:CreateBucket", "s3:CopyObject",
        "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
        "s3:GetBucketAcl", "s3:PutBucketAcl",
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
        "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan",
        "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem",
        "dynamodb:CreateTable", "dynamodb:DeleteTable",
        "lambda:InvokeFunction", "lambda:CreateFunction", "lambda:DeleteFunction",
        "lambda:UpdateFunctionCode", "lambda:GetFunction",
        "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy",
        "iam:DetachRolePolicy", "iam:CreatePolicy", "iam:DeletePolicy",
        "iam:CreateAccessKey", "iam:DeleteAccessKey",
        "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey",
        "kms:DescribeKey", "kms:CreateKey", "kms:ScheduleKeyDeletion",
        "sts:AssumeRole", "sts:GetCallerIdentity",
        "sns:Publish", "sns:Subscribe", "sns:CreateTopic", "sns:DeleteTopic",
        "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
        "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:GetQueueUrl",
        "secretsmanager:GetSecretValue", "secretsmanager:CreateSecret",
        "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret",
        "ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter",
        "events:PutEvents", "events:PutRule", "events:PutTargets",
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
        "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
    ],
    "s3:*": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:DeleteBucket",
        "s3:ListBucket", "s3:CreateBucket", "s3:CopyObject",
        "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
        "s3:GetBucketAcl", "s3:PutBucketAcl", "s3:ListAllMyBuckets",
        "s3:GetBucketVersioning", "s3:PutBucketVersioning",
        "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
    ],
    "dynamodb:*": [
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
        "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan",
        "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem",
        "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable",
        "dynamodb:ListTables", "dynamodb:TransactGetItems",
        "dynamodb:TransactWriteItems", "dynamodb:UpdateTable",
    ],
    "lambda:*": [
        "lambda:InvokeFunction", "lambda:CreateFunction", "lambda:DeleteFunction",
        "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
        "lambda:GetFunction", "lambda:ListFunctions",
        "lambda:AddPermission", "lambda:RemovePermission",
    ],
    "iam:*": [
        "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:ListRoles",
        "iam:AttachRolePolicy", "iam:DetachRolePolicy",
        "iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy",
        "iam:CreateUser", "iam:DeleteUser", "iam:GetUser",
        "iam:CreateAccessKey", "iam:DeleteAccessKey",
        "iam:PutRolePolicy", "iam:DeleteRolePolicy",
    ],
    "kms:*": [
        "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey",
        "kms:ListKeys", "kms:CreateKey", "kms:ScheduleKeyDeletion",
        "kms:Sign", "kms:Verify", "kms:GetKeyPolicy", "kms:PutKeyPolicy",
        "kms:EnableKey", "kms:DisableKey",
    ],
    "sns:*": [
        "sns:Publish", "sns:Subscribe", "sns:Unsubscribe",
        "sns:CreateTopic", "sns:DeleteTopic", "sns:ListTopics",
        "sns:GetTopicAttributes", "sns:SetTopicAttributes",
        "sns:ListSubscriptions", "sns:ConfirmSubscription",
    ],
    "sqs:*": [
        "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
        "sqs:DeleteMessageBatch", "sqs:SendMessageBatch",
        "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:GetQueueUrl",
        "sqs:GetQueueAttributes", "sqs:SetQueueAttributes",
        "sqs:ListQueues", "sqs:PurgeQueue", "sqs:ChangeMessageVisibility",
    ],
    "secretsmanager:*": [
        "secretsmanager:GetSecretValue", "secretsmanager:CreateSecret",
        "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "secretsmanager:PutSecretValue", "secretsmanager:RotateSecret",
    ],
    "ssm:*": [
        "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
        "ssm:PutParameter", "ssm:DeleteParameter", "ssm:DescribeParameters",
        "ssm:SendCommand", "ssm:ListCommands",
    ],
    "events:*": [
        "events:PutEvents", "events:PutRule", "events:DeleteRule",
        "events:PutTargets", "events:RemoveTargets", "events:ListRules",
        "events:DescribeRule", "events:EnableRule", "events:DisableRule",
    ],
    "logs:*": [
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
        "logs:GetLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams",
        "logs:FilterLogEvents", "logs:DeleteLogGroup", "logs:StartQuery",
        "logs:GetQueryResults",
    ],
    "states:*": [
        "states:StartExecution", "states:StopExecution",
        "states:DescribeExecution", "states:ListExecutions",
        "states:GetExecutionHistory", "states:CreateStateMachine",
        "states:DeleteStateMachine", "states:UpdateStateMachine",
    ],
    "ec2:*": [
        "ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances",
        "ec2:TerminateInstances", "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
        "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:RunInstances",
    ],
}


def _expand_actions(actions: list[str]) -> list[str]:
    expanded = []
    for action in actions:
        if "*" in action:
            known = WILDCARD_EXPANSIONS.get(action)
            if known:
                expanded.extend(known)
            else:
                expanded.append(action)
        else:
            expanded.append(action)
    return sorted(set(expanded))


class PatchResult:
    def __init__(
        self,
        original_tf: str,
        patched_tf: str,
        removed_actions: list[str],
        patch_risk: str,
        role_name: str,
        requires_human_review: bool,
    ):
        self.original_tf = original_tf
        self.patched_tf = patched_tf
        self.removed_actions = removed_actions
        self.patch_risk = patch_risk
        self.role_name = role_name
        self.requires_human_review = requires_human_review
        self.changed = original_tf != patched_tf

    def summary(self) -> str:
        lines = [
            f"Role: {self.role_name}",
            f"Patch risk: {self.patch_risk}",
            f"Permissions removed: {len(self.removed_actions)}",
            f"Requires human review: {self.requires_human_review}",
        ]
        if self.removed_actions:
            lines.append("Actions removed:")
            for a in sorted(self.removed_actions):
                lines.append(f"  - {a}")
        return "\n".join(lines)

    def diff(self) -> str:
        original_lines = self.original_tf.splitlines()
        patched_lines = self.patched_tf.splitlines()
        original_set = set(original_lines)
        patched_set = set(patched_lines)
        diff_lines = []
        for line in original_lines:
            if line not in patched_set:
                diff_lines.append(f"- {line}")
        for line in patched_lines:
            if line not in original_set:
                diff_lines.append(f"+ {line}")
        return "\n".join(diff_lines) if diff_lines else "(no changes)"


def generate_patch(delta: DeltaResult, tf_file_path: str) -> PatchResult:
    """
    Main entry point.
    ABORTS if requires_human_review=True — blind spots mean patch is unsafe.
    """
    path = Path(tf_file_path)
    original_content = path.read_text(encoding="utf-8")

    if delta.requires_human_review:
        return PatchResult(
            original_tf=original_content,
            patched_tf=original_content,
            removed_actions=[],
            patch_risk=delta.patch_risk,
            role_name=delta.role_name,
            requires_human_review=True,
        )

    action_excess = {
        e.action_iam
        for e in delta.excess
        if e.over_privilege_type.value == "action"
    }

    if not action_excess:
        return PatchResult(
            original_tf=original_content,
            patched_tf=original_content,
            removed_actions=[],
            patch_risk=delta.patch_risk,
            role_name=delta.role_name,
            requires_human_review=delta.requires_human_review,
        )

    patched_content = _patch_policy_in_tf(original_content, action_excess)
    actually_removed = sorted(action_excess) if patched_content != original_content else []

    return PatchResult(
        original_tf=original_content,
        patched_tf=patched_content,
        removed_actions=actually_removed,
        patch_risk=delta.patch_risk,
        role_name=delta.role_name,
        requires_human_review=delta.requires_human_review,
    )


def _patch_policy_in_tf(tf_content: str, actions_to_remove: set[str]) -> str:
    def replace_policy(match: re.Match) -> str:
        prefix = match.group(1)
        policy_json = match.group(2)
        suffix = match.group(3)

        try:
            unescaped = policy_json.replace('\\"', '"')
            policy_doc = json.loads(unescaped)
        except json.JSONDecodeError:
            return match.group(0)

        modified = False
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            raw_actions = stmt.get("Action", [])
            if isinstance(raw_actions, str):
                raw_actions = [raw_actions]

            expanded = _expand_actions(raw_actions)
            filtered = [a for a in expanded if a not in actions_to_remove]

            if filtered != raw_actions:
                stmt["Action"] = sorted(filtered)
                modified = True

        if not modified:
            return match.group(0)

        new_json = json.dumps(policy_doc, separators=(",", ":"))
        new_escaped = new_json.replace('"', '\\"')
        return f"{prefix}{new_escaped}{suffix}"

    pattern = r'(policy\s*=\s*")((?:[^"\\]|\\.)*?)(")'
    return re.sub(pattern, replace_policy, tf_content)