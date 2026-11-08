"""Sandboxed command execution.

Every command runs with: the working directory pinned inside a jail root,
a scrubbed environment (no inherited secrets), a hard timeout, and a byte cap
on captured output. The jail check resolves symlinks, so ../ tricks and
symlink escapes both fail closed.
"""

import os
import subprocess

DEFAULT_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}
MAX_OUTPUT = 200_000


class JailError(Exception):
    pass


def resolve_in_jail(root: str, path: str = ".") -> str:
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(base, path))
    if not (target == base or target.startswith(base + os.sep)):
        raise JailError(f"path escapes jail: {path}")
    return target


def run_command(argv, root: str, timeout: float = 30.0, env: dict | None = None) -> dict:
    """Run argv (list, never a shell string) inside the jail. Returns a result
    dict; never raises for command failure itself."""
    cwd = resolve_in_jail(root)
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, env=env or dict(DEFAULT_ENV),
            capture_output=True, timeout=timeout, text=True,
            errors="replace",
        )
        return {"ok": proc.returncode == 0, "exit": proc.returncode,
                "stdout": proc.stdout[:MAX_OUTPUT], "stderr": proc.stderr[:MAX_OUTPUT],
                "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit": None, "stdout": "", "stderr": "timeout",
                "timed_out": True}
    except FileNotFoundError as e:
        return {"ok": False, "exit": None, "stdout": "", "stderr": str(e),
                "timed_out": False}
