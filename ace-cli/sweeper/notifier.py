"""
sweeper/notifier.py — email notification for PENDING_REDUCTION state.
v1: sends via SMTP using ACE_SMTP_* env vars.
v2: Slack/webhook fallback hierarchy (future).
"""

import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger("sweeper.notifier")

COOLING_OFF_DAYS = 14


def notify_pending_reduction(
    role_arn: str,
    role_name: str,
    created_by_email: str | None,
    repo: str,
    excess_actions: list[str],
) -> bool:
    """
    Sends notification email when dormancy detected.
    Returns True if sent, False if skipped (no email configured).
    Never raises — notification failure must never block the state transition.
    """
    if not created_by_email:
        log.warning(f"No email for {role_arn} — notification skipped")
        return False

    smtp_host = os.environ.get("ACE_SMTP_HOST")
    smtp_port = int(os.environ.get("ACE_SMTP_PORT", "587"))
    smtp_user = os.environ.get("ACE_SMTP_USER")
    smtp_pass = os.environ.get("ACE_SMTP_PASS")
    from_addr = os.environ.get("ACE_SMTP_FROM", smtp_user or "ace@noreply.com")

    if not smtp_host or not smtp_user:
        log.warning("SMTP not configured — notification skipped")
        return False

    subject = f"[ACE] IAM role may be over-privileged: {role_name}"

    excess_list = "\n".join(f"  - {a}" for a in excess_actions[:20])
    if len(excess_actions) > 20:
        excess_list += f"\n  ... and {len(excess_actions) - 20} more"

    body = f"""ACE has detected that the following IAM role may have unused permissions:

Role: {role_name}
ARN:  {role_arn}
Repo: {repo}

Potentially unused permissions:
{excess_list}

A {COOLING_OFF_DAYS}-day review period has started.

What this means:
- ACE will monitor this role for {COOLING_OFF_DAYS} days
- If the role shows activity during this period, no action will be taken
- If no activity is detected after {COOLING_OFF_DAYS} days, ACE will open a PR
  to remove the unused permissions for human review

If this role is used infrequently (quarterly jobs, DR scripts, break-glass access),
add this tag to your Terraform resource:

  tags = {{
    ACE_Dormancy_Ignore = "true"
  }}

This will permanently exclude it from dormancy checks.

— ACE Sweeper
"""

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = created_by_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, created_by_email, msg.as_string())
        log.info(f"Notification sent to {created_by_email} for {role_arn}")
        return True
    except Exception as e:
        log.error(f"Email failed for {role_arn}: {e}")
        return False