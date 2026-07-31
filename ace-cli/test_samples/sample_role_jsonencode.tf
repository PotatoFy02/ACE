# sample_role_jsonencode.tf
# Tests the jsonencode() fallback path in gpm_engine.py.
# This is how real enterprise Terraform writes IAM policies.
# The parser must NOT crash or return empty on this file.
# It must return the role with requires_human_review=True.

resource "aws_iam_role" "billing_lambda" {
  name = "billing-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "billing_lambda_policy" {
  name = "billing-lambda-policy"
  role = aws_iam_role.billing_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:DeleteBucket",
        "dynamodb:PutItem",
        "dynamodb:DeleteTable"
      ]
      Resource = "*"
    }]
  })
}