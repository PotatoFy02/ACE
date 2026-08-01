import os
import json
import logging
import requests

log = logging.getLogger("sweeper.notifier")

COOLING_OFF_DAYS = 14

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL = os.environ.get("SLACK_ALERT_CHANNEL", "#security-alerts")

ACE_BASE_URL = os.environ.get("ACE_BASE_URL", "https://ace-i9mz.onrender.com")

TIMEOUT = 10


def _excess_block(excess_actions: list[str]) -> str:
    """Format excess actions as a compact Slack mrkdwn string."""
    shown = excess_actions[:15]
    lines = "\n".join(f"• `{a}`" for a in shown)
    if len(excess_actions) > 15:
        lines += f"\n_...and {len(excess_actions) - 15} more_"
    return lines


def _build_blocks(
    role_arn: str,
    role_name: str,
    repo: str,
    excess_actions: list[str],
    include_buttons: bool = False,
) -> list[dict]:
    """Build Slack Block Kit blocks for PENDING_REDUCTION notification."""
    excess_text = _excess_block(excess_actions)

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "⚠️ ACE: IAM Role May Be Over-Privileged",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Role:*\n`{role_name}`"},
                {"type": "mrkdwn", "text": f"*Repo:*\n`{repo}`"},
                {"type": "mrkdwn", "text": f"*ARN:*\n`{role_arn}`"},
                {"type": "mrkdwn", "text": f"*Review window:*\n{COOLING_OFF_DAYS} days"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Potentially unused permissions:*\n{excess_text}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"ACE will monitor this role for *{COOLING_OFF_DAYS} days*. "
                    "If no activity is detected, a PR will be opened to remove unused permissions.\n\n"
                    "If this role is used infrequently (quarterly jobs, DR scripts, break-glass), "
                    "add `ACE_Dormancy_Ignore = \"true\"` to its Terraform tags to exclude it permanently."
                ),
            },
        },
    ]

    if include_buttons:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve Reduction", "emoji": True},
                        "style": "primary",
                        "action_id": "ace_approve_reduction",
                        "value": role_arn,
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Approve permission reduction?"},
                            "text": {"type": "mrkdwn", "text": f"This will allow ACE to open a PR removing unused permissions from `{role_name}`."},
                            "confirm": {"type": "plain_text", "text": "Approve"},
                            "deny": {"type": "plain_text", "text": "Cancel"},
                        },
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🚫 Ignore", "emoji": True},
                        "style": "danger",
                        "action_id": "ace_ignore_reduction",
                        "value": role_arn,
                    },
                ],
            }
        )
    else:
        # No bot token — link to dashboard instead of buttons
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"To approve or ignore this finding, visit <{ACE_BASE_URL}|ACE Dashboard>. To enable Approve/Ignore buttons here, set `SLACK_BOT_TOKEN`.",
                    }
                ],
            }
        )

    return blocks


def _send_webhook(blocks: list[dict], text: str) -> bool:
    """Send to a Slack incoming webhook URL. No interactivity."""
    if not SLACK_WEBHOOK_URL:
        return False
    try:
        r = requests.post(
            SLACK_WEBHOOK_URL,
            json={"text": text, "blocks": blocks},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            log.error("Slack webhook returned %d: %s", r.status_code, r.text)
            return False
        return True
    except Exception as e:
        log.error("Slack webhook request failed: %s", e)
        return False


def _send_dm(owner_slack_id: str, blocks: list[dict], text: str) -> bool:
    """Send a DM to a specific Slack user via bot token. Supports buttons."""
    if not SLACK_BOT_TOKEN:
        return False
    try:
        r = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "channel": owner_slack_id,
                "text": text,
                "blocks": blocks,
            },
            timeout=TIMEOUT,
        )
        data = r.json()
        if not data.get("ok"):
            log.error("Slack DM failed: %s", data.get("error"))
            return False
        return True
    except Exception as e:
        log.error("Slack DM request failed: %s", e)
        return False


def notify_pending_reduction(
    role_arn: str,
    role_name: str,
    owner_slack_id: str | None,
    repo: str,
    excess_actions: list[str],
) -> bool:
    """
    Sends Slack notification when dormancy is detected (PENDING_REDUCTION state).

    If SLACK_BOT_TOKEN is set and owner_slack_id is provided:
      → DMs the role owner directly with Approve/Ignore buttons.

    If only SLACK_WEBHOOK_URL is set:
      → Posts to the configured channel without interactive buttons.

    Returns True if sent, False if skipped or failed.
    Never raises — notification failure must never block the state transition.
    """
    if not SLACK_WEBHOOK_URL and not SLACK_BOT_TOKEN:
        log.warning("No Slack config found (SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN) — notification skipped for %s", role_arn)
        return False

    fallback_text = f"[ACE] IAM role `{role_name}` may be over-privileged. {COOLING_OFF_DAYS}-day review period started."

    # Prefer DM with buttons if we have a bot token and the owner's Slack ID
    if SLACK_BOT_TOKEN and owner_slack_id:
        blocks = _build_blocks(role_arn, role_name, repo, excess_actions, include_buttons=True)
        sent = _send_dm(owner_slack_id, blocks, fallback_text)
        if sent:
            log.info("Slack DM sent to %s for role %s", owner_slack_id, role_arn)
            return True
        log.warning("Slack DM failed for %s, falling back to webhook", owner_slack_id)

    # Fall back to webhook (no buttons)
    blocks = _build_blocks(role_arn, role_name, repo, excess_actions, include_buttons=False)
    sent = _send_webhook(blocks, fallback_text)
    if sent:
        log.info("Slack webhook notification sent for role %s", role_arn)
        return True

    log.error("All Slack notification methods failed for role %s", role_arn)
    return False


def notify_pr_opened(
    role_arn: str,
    role_name: str,
    owner_slack_id: str | None,
    pr_url: str,
    commit_sha: str,
) -> bool:
    """
    Sends confirmation to Slack when ACE opens a PR for a role reduction.
    Called by the sweeper after PR is created.
    Never raises.
    """
    if not SLACK_WEBHOOK_URL and not SLACK_BOT_TOKEN:
        return False

    fallback_text = f"[ACE] PR opened to reduce permissions on `{role_name}`: {pr_url}"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "✅ ACE: Permission Reduction PR Opened",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Role:*\n`{role_name}`"},
                {"type": "mrkdwn", "text": f"*ARN:*\n`{role_arn}`"},
                {"type": "mrkdwn", "text": f"*Commit SHA:*\n`{commit_sha[:12]}`"},
                {"type": "mrkdwn", "text": f"*PR:*\n<{pr_url}|Review & Merge>"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "This PR requires human review and approval before merging. The commit SHA is recorded and cannot be backdated.",
                }
            ],
        },
    ]

    # Try DM first if we have the owner
    if SLACK_BOT_TOKEN and owner_slack_id:
        sent = _send_dm(owner_slack_id, blocks, fallback_text)
        if sent:
            log.info("PR opened DM sent to %s for role %s", owner_slack_id, role_arn)
            return True

    # Fall back to channel webhook
    sent = _send_webhook(blocks, fallback_text)
    if sent:
        log.info("PR opened webhook notification sent for role %s", role_arn)
        return True

    log.error("All Slack notification methods failed (PR opened) for role %s", role_arn)
    return False