"""
Severity lookup table for IAM actions.
Delta Engine assigns severity — never the parser.
"""

from schemas.models import Severity

# HIGH: actions that can destroy data, exfiltrate credentials,
#       escalate privileges, or cause irreversible damage
HIGH_ACTIONS: set[str] = {
    # S3 destructive
    "s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteBucketPolicy",
    "s3:PutBucketPolicy", "s3:PutBucketAcl",
    # IAM privilege escalation
    "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy",
    "iam:DetachRolePolicy", "iam:CreatePolicy", "iam:DeletePolicy",
    "iam:CreateUser", "iam:DeleteUser", "iam:CreateAccessKey",
    "iam:PutRolePolicy", "iam:PassRole",
    # STS
    "sts:AssumeRole",
    # KMS
    "kms:Decrypt", "kms:GenerateDataKey", "kms:CreateKey",
    "kms:ScheduleKeyDeletion",
    # DynamoDB destructive
    "dynamodb:DeleteTable", "dynamodb:DeleteItem",
    # Lambda destructive
    "lambda:DeleteFunction", "lambda:AddPermission",
    # EC2
    "ec2:TerminateInstances", "ec2:DeleteSecurityGroup",
    # Secrets
    "secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret",
}

# MEDIUM: actions that mutate state or write data
MEDIUM_ACTIONS: set[str] = {
    "s3:PutObject", "s3:CopyObject",
    "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:BatchWriteItem",
    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
    "lambda:CreateFunction", "lambda:InvokeFunction",
    "sns:Publish", "sqs:SendMessage",
    "ses:SendEmail", "sesv2:SendEmail",
    "ssm:PutParameter",
    "events:PutEvents", "events:PutRule",
    "logs:CreateLogGroup", "logs:PutLogEvents",
    "kinesis:PutRecord", "kinesis:PutRecords",
    "firehose:PutRecord",
    "stepfunctions:StartExecution",
    "bedrock:InvokeModel",
}


def get_severity(action_iam: str) -> Severity:
    """
    Returns severity for a given IAM action.
    HIGH > MEDIUM > LOW.
    Unknown actions default to MEDIUM — safer than LOW for unknown blast radius.
    """
    if action_iam in HIGH_ACTIONS:
        return Severity.HIGH
    if action_iam in MEDIUM_ACTIONS:
        return Severity.MEDIUM
    return Severity.LOW