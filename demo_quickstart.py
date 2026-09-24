#!/usr/bin/env python3
"""
Haldir demo — one file, one command, nothing to arrange.

    python3 demo_quickstart.py

Creates a throwaway virtualenv, installs Haldir into it, starts an instance,
runs the three probes against it, and deletes the lot. Python 3.10+ is the
only requirement: no clone, no `pip install`, no account, no config. Nothing
it creates outlives the run.

    python3 demo_quickstart.py --keep

Same setup, but leaves the instance up and prints the URL, so you can browse
the in-browser demo at /demo and the tamper demo at /demo/tamper. Ctrl-C
stops it and removes everything.

    python3 demo_quickstart.py --from ./haldir-0.3.2-py3-none-any.whl

Install from a wheel or a path instead of PyPI — for testing a build that
has not been released yet, which today is any build containing the probes.

## Why this is a bootstrap and not a bundled program

The probes live in `haldir_probes.py`, which ships inside the package. This
file installs the package and then runs that module, so there is one copy of
the probe code rather than a version vendored here that drifts from it. The
cost is a pip install on first run; the alternative is two copies of the
thing under test.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

MIN_PYTHON = (3, 10)
DEFAULT_REQUIREMENT = "haldir"

# True inside a PyInstaller build. It matters because a frozen binary is not
# an interpreter: `sys.executable` is the binary itself, and it has no `-m`,
# so nothing here can re-invoke the CLI or the probes as modules. Both are
# reached differently in that case — see server_command() and run_probes().
IS_FROZEN = bool(getattr(sys, "frozen", False))


def source_tree() -> str | None:
    """The checkout this file lives in, if it is one.

    Running the launcher from a clone should use the clone, not install a
    second copy of it from PyPI — slower, and a different version from the
    one being looked at.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(here, "cli.py")):
        return here
    return None


def child_env() -> dict[str, str]:
    """The environment for processes that have to import Haldir."""
    env = dict(os.environ)
    # Child processes print the same characters; PYTHONIOENCODING is how the
    # setting crosses a process boundary, since they start fresh interpreters.
    env.setdefault("PYTHONIOENCODING", "utf-8")
    tree = source_tree()
    if tree:
        prior = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{tree}{os.pathsep}{prior}" if prior else tree
    return env


def haldir_available(python: str) -> bool:
    """Can `python` import Haldir?

    Asked of a subprocess from a neutral directory rather than by importing
    it here. Python puts the *script's* own directory on sys.path, so running
    this file from a checkout makes `cli` importable in this process while a
    subprocess started anywhere else cannot find it — and it is the
    subprocess that has to import it. Checking in-process reported success
    and then died on `No module named haldir_probes`.

    A bundled build carries Haldir in its archive, so there is nothing to
    check there and nothing to install.
    """
    if IS_FROZEN:
        return True
    return subprocess.run(
        [python, "-c", "import cli, haldir_probes"],
        capture_output=True, cwd=tempfile.gettempdir(), env=child_env(),
    ).returncode == 0


def force_utf8_output() -> None:
    """Make stdout and stderr UTF-8 on platforms that do not default to it.

    Windows consoles and redirected pipes use a legacy codepage (cp1252 and
    friends) unless told otherwise, and this program prints em dashes, box
    drawing and `·`. A `print` that cannot encode a character raises
    UnicodeEncodeError and takes the whole run with it — the bundled binary
    died on Windows twice: once on SIGHUP, then on this.

    `errors="replace"` rather than strict, so a console that still cannot
    render a glyph shows a placeholder instead of failing. Losing a dash is
    survivable; losing the run is not.
    """
    for stream in (sys.stdout, sys.stderr):
        # getattr rather than a direct call: `reconfigure` is on
        # io.TextIOWrapper, not on the TextIO protocol sys.stdout is typed as,
        # so mypy is right that it may not be there.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass   # not a TextIOWrapper, or already detached


def info(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def good(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def bad(msg: str) -> None:
    print(f"[-] {msg}", file=sys.stderr, flush=True)


def die(msg: str, detail: str = "") -> None:
    bad(msg)
    if detail.strip():
        print("\n" + detail.strip()[-1500:], file=sys.stderr)
    raise SystemExit(1)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def venv_python(venv_dir: str) -> str:
    """The interpreter inside a venv, on either layout."""
    for rel in (("bin", "python"), ("Scripts", "python.exe")):
        candidate = os.path.join(venv_dir, *rel)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(venv_dir, "bin", "python")


def make_venv(venv_dir: str) -> str:
    info(f"creating a throwaway virtualenv ({venv_dir})")
    r = subprocess.run(
        [sys.executable, "-m", "venv", venv_dir],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        # The usual cause on Debian and Ubuntu is the split-out package, and
        # the error venv gives does not name it.
        die(
            "could not create a virtualenv.",
            r.stderr + "\nOn Debian/Ubuntu this is usually the missing "
            "python3-venv package:\n    sudo apt install python3-venv",
        )
    return venv_python(venv_dir)


def pip_install(python: str, requirement: str) -> None:
    info(f"installing {requirement} — this is the slow part, up to a minute or so")
    r = subprocess.run(
        [python, "-m", "pip", "install", "--quiet",
         "--disable-pip-version-check", requirement],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        die(f"could not install {requirement!r}.", r.stderr)


def wait_for(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=2):
                return True
        except Exception:
            time.sleep(0.3)
    return False


def run_probes(python: str) -> int:
    """Hand over to the fixture, which starts its own instance and cleans up.

    Its output goes straight to this terminal — the probes print the raw
    responses behind each verdict, and buffering them through a pipe would
    lose that ordering against the progress lines here.
    """
    if IS_FROZEN:
        # The launcher owns the server, not the probe module. A frozen binary
        # cannot re-invoke `haldir_probes` with `-m`, so the alternative is a
        # frozen-only spawn path inside the module — a packaging concern
        # sitting in the thing under test. It already knows how to probe an
        # instance it did not start; that is the path used here.
        import haldir_probes
        with running_instance(python) as (base, db_path):
            return haldir_probes.main(["--base", base, "--db", db_path])
    return subprocess.run(
        [python, "-m", "haldir_probes", "--serve"], env=child_env(),
    ).returncode


def server_command(python: str, port: int, data_dir: str) -> list[str]:
    """The argv that starts a Haldir server, in whichever world we are in.

    Frozen, the only program here is this binary, so it re-enters itself
    through a flag that is not advertised — a tester has no reason to run the
    server half on its own, and the fresh virtualenv path does it a
    different way.
    """
    if IS_FROZEN:
        return [sys.executable, "--run-server",
                "--port", str(port), "--data-dir", data_dir]
    return [python, "-m", "cli", "serve",
            "--port", str(port), "--data-dir", data_dir, "--no-key"]


def mint_demo_key(base: str) -> str | None:
    """A sandbox key, so the instance can be used rather than only looked at.

    Without one a tester can browse /demo — which mints its own keys — but
    cannot point curl, their own agent, or the MCP proxy at the instance.
    """
    req = urllib.request.Request(base + "/v1/demo/key", data=b"{}", method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("key")
    except Exception:
        return None


def _stop(proc: subprocess.Popen, data_dir: str) -> None:
    """Stop a server and delete what it wrote."""
    # Signals ignored first, so a Ctrl-C during teardown cannot interrupt the
    # teardown and leave the directory behind.
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(data_dir, ignore_errors=True)


@contextlib.contextmanager
def running_instance(python: str):
    """A server, up for the duration of the block. Yields (base_url, db_path).

    The launcher owns process management, and that is what keeps the frozen
    build from needing a second spawn path inside `haldir_probes`. A frozen
    binary cannot re-invoke a module with `-m`, so the probe module would
    otherwise need its own frozen-only branch — putting a packaging concern
    inside the thing under test.
    """
    port = free_port()
    data_dir = tempfile.mkdtemp(prefix="haldir-demo-")
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        server_command(python, port, data_dir),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=child_env(),
    )
    try:
        if not wait_for(base):
            die("the instance did not answer /healthz within 30s.")
        yield base, os.path.join(data_dir, "haldir.db")
    finally:
        _stop(proc, data_dir)


def run_kept_instance(python: str) -> int:
    """Start an instance, print how to use it, and wait until Ctrl-C."""
    try:
        with running_instance(python) as (base, _db):
            good(f"Haldir is running at {base}")
            _tinker_banner(base)
            while True:
                time.sleep(0.3)
    except KeyboardInterrupt:
        print()
        info("stopping")
        return 0


def _tinker_banner(base: str) -> None:
    """Everything a tester needs to *use* the instance, not just look at it.

    A page you can only read is a demo; this is a real instance with a real
    key, so the commands below are printed because they can be pasted into
    another terminal and work. That is the difference between showing someone
    governance and letting them try to break it.

    Flushed line by line — without that the banner sits in a pipe buffer
    while the process waits on Ctrl-C, and anyone who redirected the output
    never sees the address this exists to print.
    """
    key = mint_demo_key(base)
    shown = key or "hld_...  (minting failed — POST /v1/demo/key for one)"
    for line in (
        "",
        f"    In-browser demo   {base}/demo",
        f"    Tamper demo       {base}/demo/tamper",
        f"    API reference     {base}/docs",
        "",
        f"    API key           {shown}",
        "                      free tier — one agent, 10,000 calls a month",
        "",
        "    It is a real instance, so point whatever you like at it:",
        "",
        f"      export HALDIR_BASE_URL={base}",
        f"      export HALDIR_API_KEY={key or 'hld_...'}",
        "",
        "      # open a governed session",
        "      curl -s -X POST $HALDIR_BASE_URL/v1/sessions \\",
        '        -H "Authorization: Bearer $HALDIR_API_KEY" \\',
        "        -H 'Content-Type: application/json' \\",
        '        -d \'{"agent_id":"my-agent",'
        '"scopes":["read","execute"],"spend_limit":5.00}\'',
        "",
        "      # has anything been edited since it was written?",
        "      curl -s $HALDIR_BASE_URL/v1/audit/verify \\",
        '        -H "Authorization: Bearer $HALDIR_API_KEY"',
        "",
        "      # or from Python",
        "      from haldir import HaldirClient",
        f'      h = HaldirClient(api_key="{key or "hld_..."}", '
        f'base_url="{base}")',
        "",
        "    Ctrl-C to stop. Everything it wrote is deleted when you do.",
        "",
    ):
        print(line, flush=True)


def main() -> int:
    force_utf8_output()

    if sys.version_info < MIN_PYTHON:
        die(
            f"needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer; this is "
            f"{sys.version_info.major}.{sys.version_info.minor}."
        )

    # SIGTERM does not raise by default — it terminates the process outright,
    # so the `finally` that removes the virtualenv never runs and a killed
    # demo leaves a few hundred megabytes in /tmp. Converting it to
    # SystemExit is what makes "nothing it creates outlives the run" true for
    # `timeout`, a process manager, or a Ctrl-C from a wrapper that forwards
    # TERM rather than INT.
    def _exit_on_signal(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    # Resolved by name, not referenced directly. Windows has no SIGHUP at all,
    # so `signal.SIGHUP` raises AttributeError while the tuple is being built —
    # before the try below can catch anything, and not a type it catches. The
    # bundled binary died on this on Windows on its first run.
    for _name in ("SIGTERM", "SIGHUP"):
        _sig = getattr(signal, _name, None)
        if _sig is None:
            continue
        try:
            signal.signal(_sig, _exit_on_signal)
        except (ValueError, OSError):
            pass   # not settable from a non-main thread, among other reasons

    ap = argparse.ArgumentParser(
        description="Run a disposable Haldir demo. Installs what it needs "
                    "into a temporary virtualenv and removes it afterwards.",
    )
    ap.add_argument("--keep", action="store_true",
                    help="leave the instance running so you can browse /demo")
    ap.add_argument("--from", dest="source", default=DEFAULT_REQUIREMENT,
                    help=f"what to install (default {DEFAULT_REQUIREMENT} "
                         f"from PyPI; accepts a wheel path or a git URL)")
    # Not advertised. A frozen build has no way to invoke the CLI, so it
    # re-enters this binary through these to start the server half.
    ap.add_argument("--run-server", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=8000, help=argparse.SUPPRESS)
    ap.add_argument("--data-dir", default="", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.run_server:
        # Built through the CLI's own parser rather than a hand-made
        # Namespace, so the serve flags keep one definition and a rename
        # there cannot silently stop matching here.
        import cli
        ns = cli.build_parser().parse_args([
            "serve", "--port", str(args.port),
            "--data-dir", args.data_dir, "--no-key",
        ])
        ns.func(ns)
        return 0

    # Already importable — either installed, or running from a bundled build
    # that carries Haldir inside the archive. Building a virtualenv to hold a
    # second copy of what is already here would be the slowest possible way to
    # do nothing, and it is what lets this same file be the bundled entry
    # point rather than needing a second one.
    if haldir_available(sys.executable):
        info("Haldir is already here — no install needed")
        if args.keep:
            return run_kept_instance(sys.executable)
        return run_probes(sys.executable)

    venv_dir = tempfile.mkdtemp(prefix="haldir-demo-venv-")
    try:
        python = make_venv(venv_dir)
        pip_install(python, args.source)

        if args.keep:
            return run_kept_instance(python)
        return run_probes(python)
    finally:
        info("removing the temporary virtualenv")
        shutil.rmtree(venv_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
