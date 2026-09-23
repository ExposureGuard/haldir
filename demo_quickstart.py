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
    return subprocess.run(
        [python, "-m", "haldir_probes", "--serve"],
    ).returncode


def run_kept_instance(python: str, requirement: str) -> int:
    """Start an instance and leave it up until Ctrl-C."""
    port = free_port()
    data_dir = tempfile.mkdtemp(prefix="haldir-demo-")
    base = f"http://127.0.0.1:{port}"

    proc = subprocess.Popen(
        [python, "-m", "cli", "serve",
         "--port", str(port), "--data-dir", data_dir, "--no-key"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for(base):
            proc.terminate()
            die("the instance did not answer /healthz within 30s.")
        good(f"Haldir is running at {base}")
        # Flushed line by line. Without it the banner sits in a pipe buffer
        # while the process waits on Ctrl-C, so anyone who redirected the
        # output — or ran this under a wrapper that captures it — never sees
        # the URL it exists to print.
        for line in (
            "",
            f"    In-browser demo   {base}/demo",
            f"    Tamper demo       {base}/demo/tamper",
            f"    API reference     {base}/docs",
            "",
            "    Ctrl-C to stop. Everything below is deleted when you do.",
            f"    ({data_dir})",
            "",
        ):
            print(line, flush=True)
        while proc.poll() is None:
            time.sleep(0.3)
        return 0
    except KeyboardInterrupt:
        print()
        info("stopping")
        return 0
    finally:
        # Signal handlers first, so a Ctrl-C during teardown does not
        # interrupt the teardown and leave the directory behind.
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


def main() -> int:
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

    for _sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(_sig, _exit_on_signal)
        except (ValueError, OSError):
            pass   # not every platform has SIGHUP, and threads cannot set these

    ap = argparse.ArgumentParser(
        description="Run a disposable Haldir demo. Installs what it needs "
                    "into a temporary virtualenv and removes it afterwards.",
    )
    ap.add_argument("--keep", action="store_true",
                    help="leave the instance running so you can browse /demo")
    ap.add_argument("--from", dest="source", default=DEFAULT_REQUIREMENT,
                    help=f"what to install (default {DEFAULT_REQUIREMENT} "
                         f"from PyPI; accepts a wheel path or a git URL)")
    args = ap.parse_args()

    venv_dir = tempfile.mkdtemp(prefix="haldir-demo-venv-")
    try:
        python = make_venv(venv_dir)
        pip_install(python, args.source)

        if args.keep:
            return run_kept_instance(python, args.source)
        return run_probes(python)
    finally:
        info("removing the temporary virtualenv")
        shutil.rmtree(venv_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
