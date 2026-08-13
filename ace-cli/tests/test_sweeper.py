"""
tests/test_sweeper.py
Tests for the Sweeper state machine.
Uses mocked Supabase and AWS calls — no real network calls.
"""
from unittest.mock import patch, MagicMock
from sweeper.engine import process_role, advance_cooling_off
from sweeper.notifier import notify_pending_reduction


def make_mock_session(is_dormant: bool):
    session = MagicMock()
    iam = MagicMock()
    session.client.return_value = iam
    iam.generate_service_last_accessed_details.return_value = {"JobId": "test-job"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [] if is_dormant else [
            {"LastAuthenticated": "2026-07-01T00:00:00+00:00"}
        ],
    }
    return session


def test_notify_skips_when_no_slack_id():
    """No owner_slack_id and no Slack env vars — should return False."""
    with patch.dict("os.environ", {
        "SLACK_WEBHOOK_URL": "",
        "SLACK_BOT_TOKEN": "",
    }):
        with patch("sweeper.notifier._send_webhook", return_value=False), \
             patch("sweeper.notifier._send_dm", return_value=False):
            result = notify_pending_reduction(
                role_arn="arn:aws:iam::123:role/test",
                role_name="test-role",
                owner_slack_id=None,
                repo="test-repo",
                excess_actions=["s3:DeleteBucket"],
            )
    assert result is False


def test_notify_sends_when_configured():
    """With Slack configured and owner_slack_id set, notification should succeed."""
    with patch("sweeper.notifier._send_dm", return_value=True):
        result = notify_pending_reduction(
            role_arn="arn:aws:iam::123:role/test",
            role_name="test-role",
            owner_slack_id="U012AB3CD",
            repo="test-repo",
            excess_actions=["s3:DeleteBucket"],
        )
    assert result is True


@patch("sweeper.engine.upsert_role")
@patch("sweeper.engine.get_role")
@patch("sweeper.engine.transition")
@patch("sweeper.engine.notify_pending_reduction")
@patch("sweeper.iam_checker.check_role_dormancy")
def test_active_role_stays_active_when_not_dormant(
    mock_check, mock_notify, mock_transition, mock_get_role, mock_upsert
):
    mock_get_role.return_value = {"state": "ACTIVE", "role_arn": "arn:test"}
    mock_check.return_value = (False, None)

    state = process_role(
        role_arn="arn:test",
        role_name="test-role",
        repo="repo",
        tf_file_path="main.tf",
        owner_slack_id="U012AB3CD",
        excess_actions=[],
        ignore_dormancy=False,
        boto3_session=MagicMock(),
    )

    assert state == "ACTIVE"
    mock_transition.assert_not_called()
    mock_notify.assert_not_called()


@patch("sweeper.engine.upsert_role")
@patch("sweeper.engine.get_role")
@patch("sweeper.engine.transition")
@patch("sweeper.engine.notify_pending_reduction")
@patch("sweeper.iam_checker.check_role_dormancy")
def test_dormant_role_transitions_to_pending(
    mock_check, mock_notify, mock_transition, mock_get_role, mock_upsert
):
    mock_get_role.return_value = {"state": "ACTIVE", "role_arn": "arn:test"}
    mock_check.return_value = (True, None)
    mock_notify.return_value = True

    state = process_role(
        role_arn="arn:test",
        role_name="test-role",
        repo="repo",
        tf_file_path="main.tf",
        owner_slack_id="U012AB3CD",
        excess_actions=["s3:DeleteBucket"],
        ignore_dormancy=False,
        boto3_session=MagicMock(),
    )

    assert state == "PENDING_REDUCTION"
    mock_transition.assert_called_once()
    call_args = mock_transition.call_args
    assert call_args.kwargs["to_state"] == "PENDING_REDUCTION"
    mock_notify.assert_called_once()


@patch("sweeper.engine.upsert_role")
@patch("sweeper.engine.get_role")
@patch("sweeper.engine.transition")
@patch("sweeper.engine.notify_pending_reduction")
@patch("sweeper.iam_checker.check_role_dormancy")
def test_pending_role_resets_to_active_on_activity(
    mock_check, mock_notify, mock_transition, mock_get_role, mock_upsert
):
    mock_get_role.return_value = {
        "state": "PENDING_REDUCTION",
        "role_arn": "arn:test"
    }
    mock_check.return_value = (False, None)

    state = process_role(
        role_arn="arn:test",
        role_name="test-role",
        repo="repo",
        tf_file_path="main.tf",
        owner_slack_id="U012AB3CD",
        excess_actions=[],
        ignore_dormancy=False,
        boto3_session=MagicMock(),
    )

    assert state == "ACTIVE"
    mock_transition.assert_called_once()
    call_args = mock_transition.call_args
    assert call_args.kwargs["to_state"] == "ACTIVE"


@patch("sweeper.engine.upsert_role")
@patch("sweeper.engine.get_role")
@patch("sweeper.iam_checker.check_role_dormancy")
def test_ignore_dormancy_skips_processing(
    mock_check, mock_get_role, mock_upsert
):
    mock_get_role.return_value = {"state": "ACTIVE", "role_arn": "arn:test"}

    state = process_role(
        role_arn="arn:test",
        role_name="test-role",
        repo="repo",
        tf_file_path="main.tf",
        owner_slack_id=None,
        excess_actions=[],
        ignore_dormancy=True,
        boto3_session=MagicMock(),
    )

    assert state == "ACTIVE"
    mock_check.assert_not_called()


@patch("sweeper.engine.upsert_role")
@patch("sweeper.engine.get_role")
@patch("sweeper.iam_checker.check_role_dormancy")
def test_pr_open_role_skipped(
    mock_check, mock_get_role, mock_upsert
):
    mock_get_role.return_value = {"state": "PR_OPEN", "role_arn": "arn:test"}

    state = process_role(
        role_arn="arn:test",
        role_name="test-role",
        repo="repo",
        tf_file_path="main.tf",
        owner_slack_id=None,
        excess_actions=[],
        ignore_dormancy=False,
        boto3_session=MagicMock(),
    )

    assert state == "PR_OPEN"
    mock_check.assert_not_called()


@patch("sweeper.engine.get_pending_roles_past_cooling_off")
@patch("sweeper.engine.transition")
def test_advance_cooling_off_transitions_to_ready(mock_transition, mock_get_pending):
    mock_get_pending.return_value = [
        {"role_arn": "arn:test1", "role_name": "role1"},
        {"role_arn": "arn:test2", "role_name": "role2"},
    ]

    result = advance_cooling_off()

    assert len(result) == 2
    assert mock_transition.call_count == 2
    calls = [c.kwargs["to_state"] for c in mock_transition.call_args_list]
    assert all(s == "REDUCTION_READY" for s in calls)