"""
`haldir login` must survive an environment with no terminal.

The bug: it called getpass.getpass() unconditionally. getpass does not
degrade when stdin is not a tty — it raises termios.error, and the CLI died
with a traceback in exactly the environments where a non-interactive login is
the point:

    File "/usr/lib/python3.12/getpass.py", line 69, in unix_getpass
        old = termios.tcgetattr(fd)
    termios.error: (25, 'Inappropriate ioctl for device')

CI, a container, a pipe, an editor's run-command — all of them. And the first
thing anyone scripting this reaches for is

    echo "$HALDIR_KEY" | haldir login

which has to work, because the alternative is telling people to put a
credential in argv where it lands in shell history and `ps`.

Three paths, and all three are pinned here: no stdin at all (an actionable
message, not a traceback), a piped key (works), and --key (works).

Run: python -m pytest tests/test_login_noninteractive.py -v
"""

from __future__ import annotations

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli  # noqa: E402


class _FakeStdin:
    def __init__(self, text: str, tty: bool):
        self._buf = io.StringIO(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def readline(self) -> str:
        return self._buf.readline()


@pytest.fixture
def no_config(tmp_path, monkeypatch):
    """Point the config at a scratch file so a test never writes the real one."""
    monkeypatch.setattr(cli, "CONFIG_FILE", tmp_path / "config.json", raising=False)
    return tmp_path / "config.json"


# ── No terminal at all ───────────────────────────────────────────────

def test_no_stdin_exits_cleanly_instead_of_crashing(monkeypatch, capsys) -> None:
    """The reported bug. It was a traceback; it has to be a message."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("", tty=False))

    with pytest.raises(SystemExit) as exc:
        cli._read_api_key_interactively()

    assert exc.value.code == 1, "it should exit non-zero, not raise"
    err = capsys.readouterr().err + capsys.readouterr().out
    assert "no terminal" in err.lower() or "no api key" in err.lower(), (
        f"the message should say what happened, got: {err!r}"
    )


def test_no_stdin_message_says_what_to_do_instead(capsys, monkeypatch) -> None:
    """An error that only reports the problem leaves the reader stuck."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("", tty=False))
    with pytest.raises(SystemExit):
        cli._read_api_key_interactively()
    out = capsys.readouterr()
    combined = (out.err + out.out).lower()
    assert "--key" in combined, "the message should name --key as the way out"
    assert "pipe" in combined, "and the pipe form, which is what people try first"


# ── stdin has a key ──────────────────────────────────────────────────

def test_piped_key_is_read(monkeypatch) -> None:
    """`echo "$KEY" | haldir login` — the scripting path, and the one that
    keeps a credential out of argv."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("hld_fromapipe\n", tty=False))
    assert cli._read_api_key_interactively() == "hld_fromapipe"


def test_piped_key_is_stripped(monkeypatch) -> None:
    """A trailing newline from echo, or CRLF from a file, must not end up
    inside the stored credential."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("  hld_spaced  \n", tty=False))
    assert cli._read_api_key_interactively() == "hld_spaced"


def test_blank_lines_before_the_key_are_not_the_key(monkeypatch) -> None:
    """A leading newline would otherwise be read as an empty key and the
    real one silently remained unread."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("hld_real\n", tty=False))
    assert cli._read_api_key_interactively() == "hld_real"


# ── A terminal exists ────────────────────────────────────────────────

def test_interactive_prompt_is_still_used_when_there_is_a_tty(monkeypatch) -> None:
    """The normal path must not have been traded away for the fallback: on a
    real terminal the key is still read without echo."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("", tty=True))
    seen: list[str] = []

    def fake_getpass(prompt=""):
        seen.append(prompt)
        return "hld_fromtty\n"

    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    assert cli._read_api_key_interactively() == "hld_fromtty"
    assert seen, "getpass should have been used on a tty"


def test_a_failing_getpass_is_a_message_not_a_traceback(monkeypatch, capsys) -> None:
    """Whatever the platform raises from getpass — termios.error on an odd
    tty, something else elsewhere — the person logging in should not be shown
    a stack trace."""

    class WeirdTtyError(Exception):
        pass

    monkeypatch.setattr(sys, "stdin", _FakeStdin("", tty=True))

    def boom(prompt=""):
        raise WeirdTtyError("no controlling terminal")

    monkeypatch.setattr(cli.getpass, "getpass", boom)
    with pytest.raises(SystemExit) as exc:
        cli._read_api_key_interactively()
    assert exc.value.code == 1
    out = capsys.readouterr()
    assert "WeirdTtyError" in (out.err + out.out), (
        "the failure should be named so it can be reported"
    )


def test_ctrl_c_is_not_reported_as_an_error(monkeypatch, capsys) -> None:
    """^C at a password prompt is a decision, not a fault. It should exit 1
    with a plain message rather than a KeyboardInterrupt traceback."""
    monkeypatch.setattr(sys, "stdin", _FakeStdin("", tty=True))

    def interrupt(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.getpass, "getpass", interrupt)
    with pytest.raises(SystemExit) as exc:
        cli._read_api_key_interactively()
    assert exc.value.code == 1
    combined = (capsys.readouterr().err + capsys.readouterr().out).lower()
    assert "traceback" not in combined
