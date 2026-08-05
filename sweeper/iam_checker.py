"""
sweeper/iam_checker.py — checks IAM last-used timestamps via AWS API.
Uses GetServiceLastAccessedDetails — no CloudTrail setup required.
Covers trailing 400 days. Free tier.

v2 upgrade path: replace with IAM Access Analyzer StartPolicyGeneration
for more granular per-action analysis.
"""

import logging
from datetime import datetime, timezone, timedelta

log = logging.getLogger("sweeper.iam_checker")

DORMANCY_DAYS = 90


def check_role_dormancy(
    role_arn: str,
    boto3_session,
) -> tuple[bool, datetime | None]:
    """
    Checks if a role is dormant using IAM last-used timestamps.

    Returns:
        (is_dormant: bool, last_used_at: datetime | None)
        is_dormant=True means no service was accessed in the last DORMANCY_DAYS days.
        last_used_at=None means the role has never been used.

    Requires: iam:GenerateServiceLastAccessedDetails + iam:GetServiceLastAccessedDetails
    """
    iam = boto3_session.client("iam")

    try:
        # Step 1: generate report
        response = iam.generate_service_last_accessed_details(Arn=role_arn)
        job_id = response["JobId"]

        # Step 2: poll until complete (usually < 5 seconds)
        import time
        for _ in range(10):
            details = iam.get_service_last_accessed_details(JobId=job_id)
            if details["JobStatus"] == "COMPLETED":
                break
            time.sleep(1)
        else:
            log.warning(f"IAM report timed out for {role_arn}")
            return (False, None)

        # Step 3: find most recent service access
        services = details.get("ServicesLastAccessed", [])
        last_used = None

        for service in services:
            accessed = service.get("LastAuthenticated")
            if accessed:
                if isinstance(accessed, str):
                    accessed = datetime.fromisoformat(accessed)
                if accessed.tzinfo is None:
                    accessed = accessed.replace(tzinfo=timezone.utc)
                if last_used is None or accessed > last_used:
                    last_used = accessed

        # Step 4: dormancy check
        cutoff = datetime.now(timezone.utc) - timedelta(days=DORMANCY_DAYS)
        if last_used is None:
            return (True, None)  # never used
        if last_used < cutoff:
            return (True, last_used)  # used but not recently
        return (False, last_used)

    except iam.exceptions.NoSuchEntityException:
        log.error(f"Role not found in AWS: {role_arn}")
        return (False, None)
    except Exception as e:
        log.error(f"IAM check failed for {role_arn}: {e}")
        return (False, None)