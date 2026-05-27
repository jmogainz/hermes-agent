from datetime import datetime
from unittest.mock import Mock

from gateway import run


def test_completion_reminder_threshold_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HERMES_COMPLETION_REMINDER_MIN_SECONDS", raising=False)

    assert run._completion_reminder_threshold_seconds() is None


def test_completion_reminder_threshold_zero_means_every_reply(monkeypatch):
    monkeypatch.setenv("HERMES_COMPLETION_REMINDER_MIN_SECONDS", "0")

    assert run._completion_reminder_threshold_seconds() == 0


def test_completion_reminder_cleanup_seconds(monkeypatch):
    monkeypatch.setenv("HERMES_COMPLETION_REMINDER_CLEANUP_SECONDS", "120")

    assert run._completion_reminder_cleanup_seconds() == 120


def test_completion_reminder_cleanup_seconds_invalid(monkeypatch):
    monkeypatch.setenv("HERMES_COMPLETION_REMINDER_CLEANUP_SECONDS", "later")

    assert run._completion_reminder_cleanup_seconds() is None


def test_completion_reminder_command_targets_current_second():
    command = run._build_completion_reminder_command(
        elapsed_seconds=125,
        api_calls=7,
        message_preview="Please do a long research task",
        response_preview="Done. Here is the summary.",
        now=datetime(2026, 5, 10, 12, 34, 20),
    )

    assert command[0].endswith("remindctl")
    assert command[1:3] == ["add", "--title"]
    assert "Goku finished your WhatsApp task (2:05)" in command
    assert "--no-input" in command
    assert "--json" in command
    assert command[command.index("--due") + 1] == "2026-05-10 12:34:20"
    assert command[command.index("--alarm") + 1] == "2026-05-10 12:34:20"
    assert "The WhatsApp reply has been delivered." in command[command.index("--notes") + 1]


def test_approval_reminder_command_reuses_transient_reminder_shape():
    command = run._build_approval_reminder_command(
        command="rm -rf build",
        description="recursive delete",
        now=datetime(2026, 5, 10, 12, 34, 20),
    )

    assert command[0].endswith("remindctl")
    assert command[1:3] == ["add", "--title"]
    assert "Goku needs command approval" in command
    assert "--no-input" in command
    assert "--json" in command
    assert command[command.index("--due") + 1] == "2026-05-10 12:34:20"
    assert command[command.index("--alarm") + 1] == "2026-05-10 12:34:20"
    notes = command[command.index("--notes") + 1]
    assert "The WhatsApp approval prompt has been delivered." in notes
    assert "Reason: recursive delete" in notes
    assert "Command: rm -rf build" in notes


def test_completion_reminder_extracts_reminder_id():
    assert run._extract_reminder_id('{"id":"abc123","title":"done"}') == "abc123"
    assert run._extract_reminder_id('{"reminder":{"uuid":"rem-1"}}') == "rem-1"
    assert run._extract_reminder_id("not json") is None


def test_completion_reminder_delete_command():
    assert run._build_completion_reminder_delete_command("/opt/homebrew/bin/remindctl", "abc123") == [
        "/opt/homebrew/bin/remindctl",
        "delete",
        "abc123",
        "--force",
        "--no-input",
        "--json",
    ]


def test_transient_reminder_state_record_and_forget(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "_hermes_home", tmp_path)

    run._record_transient_reminder(
        reminder_id="rem-1",
        remindctl_path="/opt/homebrew/bin/remindctl",
        log_label="Completion",
    )

    records = run._load_transient_reminder_records()
    assert len(records) == 1
    assert records[0]["id"] == "rem-1"
    assert records[0]["remindctl_path"] == "/opt/homebrew/bin/remindctl"
    assert records[0]["log_label"] == "Completion"

    run._forget_transient_reminder("rem-1")

    assert run._load_transient_reminder_records() == []
    assert not run._transient_reminders_state_path().exists()


def test_cleanup_recorded_transient_reminders_deletes_stale_records(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "_hermes_home", tmp_path)
    run._write_transient_reminder_records([
        {"id": "rem-1", "remindctl_path": "/opt/homebrew/bin/remindctl", "log_label": "Completion"},
        {"id": "rem-2", "remindctl_path": "/opt/homebrew/bin/remindctl", "log_label": "Approval"},
    ])
    subprocess_run = Mock(return_value=Mock(returncode=0, stdout='{}', stderr=''))
    monkeypatch.setattr(run.subprocess, "run", subprocess_run)

    assert run._cleanup_recorded_transient_reminders() == 2

    assert run._load_transient_reminder_records() == []
    assert subprocess_run.call_count == 2
    assert subprocess_run.call_args_list[0].args[0][:3] == ["/opt/homebrew/bin/remindctl", "delete", "rem-1"]
    assert subprocess_run.call_args_list[1].args[0][:3] == ["/opt/homebrew/bin/remindctl", "delete", "rem-2"]


def test_cleanup_recorded_transient_reminders_keeps_failed_records(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "_hermes_home", tmp_path)
    run._write_transient_reminder_records([
        {"id": "rem-1", "remindctl_path": "/opt/homebrew/bin/remindctl", "log_label": "Completion"},
    ])
    monkeypatch.setattr(run.subprocess, "run", Mock(return_value=Mock(returncode=1, stdout='', stderr='boom')))

    assert run._cleanup_recorded_transient_reminders() == 0

    assert [record["id"] for record in run._load_transient_reminder_records()] == ["rem-1"]


def test_messages_used_browser_tool_detects_direct_and_mcp_calls():
    assert run._messages_used_browser_tool(
        [
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "browser_navigate"}},
                ],
            }
        ]
    )
    assert run._messages_used_browser_tool(
        [
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "mcp_chrome-devtools_take_snapshot"}},
                ],
            }
        ]
    )
    assert not run._messages_used_browser_tool([{"role": "assistant", "content": "no tools"}])
