"""TerminalAgent: policy-gated command execution with an audit trail.

The planner interface is deliberately pluggable: feed steps from a script,
from agent-lab's MiniAgent, or (when model access is authorized) from an LLM.
Whatever plans, every command still passes the allowlist policy and the jail.
"""

import json
import os
import time

import shlex

from .policy import decide, split_pipeline
from .sandbox import JailError, resolve_in_jail, run_command


class TerminalAgent:
    def __init__(self, root: str, audit_path: str | None = None, allowlist: dict | None = None,
                 timeout: float = 30.0):
        self.root = os.path.realpath(root)
        self.audit_path = audit_path
        self.allowlist = allowlist
        self.timeout = timeout

    def _audit(self, record: dict) -> None:
        if not self.audit_path:
            return
        record = dict(record, ts=time.time())
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _paths_safe(self, part: str) -> tuple[bool, str]:
        """Reject parent-path tokens and redirection targets outside the jail.

        The jail pins cwd, but a shell redirect like `> ../x` would still
        escape, so redirect targets and any `..` token are checked here.
        """ 
        try:
            tokens = shlex.split(part)
        except ValueError:
            return False, "unparseable"
        for i, tok in enumerate(tokens):
            if tok in (">", ">>") and i + 1 < len(tokens):
                try:
                    resolve_in_jail(self.root, tokens[i + 1])
                except JailError:
                    return False, f"redirect target escapes jail: {tokens[i + 1]}"
            elif ".." in tok.split("/") :
                return False, f"parent path not allowed: {tok}"
            elif tok.startswith(">") and len(tok) > 1 and not tok.startswith(">>"):
                try:
                    resolve_in_jail(self.root, tok[1:])
                except JailError:
                    return False, f"redirect target escapes jail: {tok[1:]}"
        return True, "ok"

    def execute(self, command: str) -> dict:
        """Policy-check and run one command line (pipelines checked per part)."""
        parts = split_pipeline(command)
        for part in parts:
            allowed, reason = decide(part, self.allowlist)
            if allowed:
                allowed, reason = self._paths_safe(part)
            if not allowed:
                self._audit({"command": command, "decision": "denied", "reason": reason})
                return {"ok": False, "denied": True, "reason": reason,
                        "stdout": "", "stderr": f"denied: {reason}"}
        # run the full line through sh -c only after every part passed
        result = run_command(["/bin/sh", "-c", command], self.root, timeout=self.timeout)
        self._audit({"command": command, "decision": "allowed",
                     "exit": result["exit"], "timed_out": result["timed_out"]})
        return result
