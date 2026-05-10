from datetime import datetime

from gateway import run


def test_completion_reminder_threshold_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HERMES_COMPLETION_REMINDER_MIN_SECONDS", raising=False)

    assert run._completion_reminder_threshold_seconds() is None


def test_completion_reminder_threshold_zero_means_every_reply(monkeypatch):
    monkeypatch.setenv("HERMES_COMPLETION_REMINDER_MIN_SECONDS", "0")

    assert run._completion_reminder_threshold_seconds() == 0


def test_completion_reminder_command_targets_next_minute():
    command = run._build_completion_reminder_command(
        elapsed_seconds=125,
        api_calls=7,
        message_preview="Please do a long research task",
        response_preview="Done. Here is the summary.",
        now=datetime(2026, 5, 10, 12, 34, 20),
    )

    assert command[:3] == ["remindctl", "add", "--title"]
    assert "Goku finished your WhatsApp task (2m 5s)" in command
    assert "--no-input" in command
    assert command[command.index("--due") + 1] == "2026-05-10 12:35"
    assert command[command.index("--alarm") + 1] == "2026-05-10 12:35"
    assert "The WhatsApp reply has been delivered." in command[command.index("--notes") + 1]
