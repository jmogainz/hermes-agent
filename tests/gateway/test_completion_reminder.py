from datetime import datetime

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
    assert "Goku finished your WhatsApp task (2m 5s)" in command
    assert "--no-input" in command
    assert "--json" in command
    assert command[command.index("--due") + 1] == "2026-05-10 12:34:20"
    assert command[command.index("--alarm") + 1] == "2026-05-10 12:34:20"
    assert "The WhatsApp reply has been delivered." in command[command.index("--notes") + 1]


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
