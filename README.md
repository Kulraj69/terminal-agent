# terminal-agent

Sandboxed terminal execution for agents - the deterministic safety core of
project #1 ("Terminal Agent") from the TOP 1% AI projects list. Whatever
plans the commands (a script, MiniAgent, or a future authorized LLM loop),
every one of them passes the allowlist policy and the jail first.

## What it does

- **policy**: allowlist of programs with per-program validators (e.g. `find`
  without `-delete`/`-exec`), plus pipeline splitting so a chained `;`, `&&`,
  `||` or `|` is checked per part. Redirect targets and `..` paths are
  validated against the jail, closing the `echo x > ../file` escape.
- **sandbox**: cwd pinned inside a jail root (symlink-resolved), scrubbed
  environment (no inherited secrets), hard timeouts, capped output.
- **audit**: append-only JSONL of every command with its decision and exit,
  the receipt trail for review and for `data-flywheel` feedback.

## Honest scope

This is the execution-safety layer, not a kernel sandbox (no chroot/seccomp)
and not an autonomous planner. The LLM-driven planning half of a terminal
agent needs authorized model access, which is currently out of scope; the
policy gate here is what such a planner must route through regardless.

## Usage

```python
from termagent.agent import TerminalAgent

agent = TerminalAgent("workspace/", audit_path="audit.jsonl")
agent.execute("grep -r TODO . | wc -l")   # runs
agent.execute("rm -rf /")                  # denied: not allowlisted
```

## Test

```bash
python -m unittest discover -s tests
```

12 tests cover jail escapes, allowlist decisions, pipeline splitting, env
scrubbing, timeouts, redirect-target validation, and audit logging.

## Demo

`demo.py` reproduces the recorded demo run end to end, offline (standard
library only, no model calls):

    python demo.py

It executes the library's real code path and prints the same output shown in
the recorded demo video.
