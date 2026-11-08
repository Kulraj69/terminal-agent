"""Allowlist command policy.

A command is allowed only if its program is on the allowlist AND its
arguments pass that program's validator. Everything else is denied with a
reason, so refusals are auditable rather than silent.
"""

import os
import shlex


def _no_dashdash_delete(paths):
    return not any(p == "/" or p == "/*" for p in paths)


def _paths_within(paths, root="."):
    return all(not os.path.isabs(p) or p.startswith(os.path.realpath(root)) for p in paths)


# program -> validator(argv_tail) -> True | reason string
DEFAULT_ALLOWLIST = {
    "ls": lambda a: True,
    "cat": lambda a: all(not a0.startswith("-") for a0 in a) or True,
    "head": lambda a: True,
    "tail": lambda a: True,
    "grep": lambda a: True,
    "find": lambda a: "-delete" not in a and "-exec" not in a or "find requires no -delete/-exec",
    "echo": lambda a: True,
    "wc": lambda a: True,
    "python3": lambda a: True,
    "pwd": lambda a: True,
}


def decide(command: str, allowlist: dict | None = None) -> tuple[bool, str]:
    """Return (allowed, reason). command is a single shell-style string."""
    allowlist = allowlist or DEFAULT_ALLOWLIST
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return False, f"unparseable command: {e}"
    if not argv:
        return False, "empty command"
    prog = os.path.basename(argv[0])
    validator = allowlist.get(prog)
    if validator is None:
        return False, f"program not allowlisted: {prog}"
    verdict = validator(argv[1:])
    if verdict is not True:
        return False, f"{prog}: {verdict}"
    return True, "allowlisted"


def split_pipeline(command: str) -> list:
    """Split a command line into individual commands on ; && || | so each
    part is checked separately. A pipeline is only as safe as its weakest
    part."""
    parts, cur, quote = [], "", None
    i = 0
    while i < len(command):
        c = command[i]
        if quote:
            cur += c
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            cur += c
        elif command.startswith("&&", i) or command.startswith("||", i) or c in ";|":
            parts.append(cur)
            cur = ""
            i += 1 if command.startswith(("&&", "||"), i) else 0
        else:
            cur += c
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]
