# The coding-agent hook

SPEC §12.2, ADR-0008. One sentence: **the agent asks QED before it uses a
tool.**

```bash
qed install claude-code --human you@acme.com
```

That writes a `PreToolUse` hook into `.claude/settings.local.json`. From then
on every `Bash`, every file write, every MCP call and every skill goes through
the same `check_proposal` the MCP proxy, the HTTP proxy and `qed check` use,
and lands in the same chain.

## It is advisory, and it always will be

Whoever can edit those settings can delete the line that calls QED. A
prompt-injected agent with a `Write` tool can do it in one call. So every
record this adapter writes says `enforcement: advisory`, and the chain never
claims the action could not have happened.

That is ADR-001's class A, and it is not a reason to skip the adapter: a hook
is the only thing that sees a shell command or a file write, and most of what
a coding agent does is one of those.

**To harden it** (not to make it enforcing), deploy the same entry through
Claude Code's managed settings and set `allowManagedHooksOnly: true`. Managed
hooks cannot be removed by user, project, local or plugin settings, and
`disableAllHooks` cannot switch them off from outside managed settings.

**To actually enforce**, the agent has to be unable to reach the target
without QED — `qed proxy` plus the credential broker, ADR-001's class C.

## What it answers

| Verdict | What the agent sees | Exit |
|---|---|---|
| ALLOW | nothing at all | 0 |
| REQUIRE_APPROVAL | `permissionDecision: ask`, with the rules and the approval id | 0 |
| BLOCK | `permissionDecision: deny`, with the rules and the fix | 2 |
| QED could not decide, `fail_mode: closed` | `deny`, `[qed ERROR] …` | 2 |
| QED could not decide, `fail_mode: open` | a notice on stderr | 0 |

Three of those rows are decisions ADR-0008 argues for; the short versions:

**ALLOW prints nothing.** The contract has a `permissionDecision: "allow"`,
and it *bypasses the permission rules you configured*. A gate that answered
`allow` to everything it did not block would be granting permissions nobody
asked it to grant — someone who had denied `Bash(rm *)` in their own settings
would find QED waving it through. Printing nothing means "no decision, carry
on with the normal permission flow", which is the honest answer from something
that was asked whether to **stop** the call.

**REQUIRE_APPROVAL asks.** SPEC §12.2 degraded this to a block because the old
contract had no way to put a question to anybody. There is a person at the
terminal; `ask` hands them the question the rule asked for. The approval is
still opened and recorded, so it can also be decided out of band with
`qed approve`, and the window then applies to the retry.

**Nothing ever exits 1.** Any non-zero exit that is not 2 is *non-blocking*:
the call proceeds and the transcript shows a small notice. So a traceback here
would not fail closed, it would fail silently open — the documentation warns
that a mistyped path "silently disables the gate". Every path out of the
adapter is a deliberate exit, and a fail-open gap writes an `ungated_window`
record so it is in the chain rather than only in your scrollback.

## What it records

SPEC §12.2's mapping, plus the rest:

| Tool | `action.kind` | `action.name` |
|---|---|---|
| `Bash` | `shell` | `shell.bash` |
| `Edit` `Write` `NotebookEdit` | `custom` | `fs.write` |
| `Read` `Glob` `Grep` | `custom` | `fs.read` |
| `Skill` | `skill` | `skill` |
| `WebFetch` `WebSearch` | `http` | `web.fetch` / `web.search` |
| `Task` | `custom` | `agent.spawn` |
| `mcp__<server>__<tool>` | `mcp_tool` | `<server>.<tool>` |
| anything else | `custom` | `tool.<Name>` |

An unmapped tool is recorded under its own name rather than ignored — the one
that silently left no record would be the one an investigation needed.

The MCP row matters: `mcp__postgres__execute_sql` becomes
`postgres.execute_sql`, which is exactly what the MCP proxy writes for the
same call, so **one rule matches the same action through either adapter**.

### Targets

- a file path **relative to the session directory** when it sits underneath
  it, so an absolute path does not carry your home directory into the chain
  and a rule written against `src/*` matches on two machines;
- a URL as itself;
- for a shell command, `host:<hostname>` — the command is the *parameters*, so
  a rule that wants it matches `action.params_redacted.command`;
- for an MCP call with no path-like argument, `mcp:<server>`.

### Identity

`--human` or `--mandate` is required, for the reason every adapter requires
it: with neither, the engine answers a synthetic `AG-IDN-007` identity BLOCK
before any rule in the bundle runs, and the chain fills with identical
verdicts that say nothing about your policy.

`agent_chain` is real rather than asserted. Claude Code sends `agent_id` and
`agent_type` only when the hook fires inside a subagent, so a chain of two —
`["claude-code@host", "sub:Explore"]` — means a subagent genuinely is acting.

## Installing

```bash
qed install claude-code --human you@acme.com --env prod      # fail-mode closed
qed install claude-code --human you@acme.com --dry-run       # print, write nothing
qed install claude-code --human you@acme.com --scope project # committed settings
```

Three properties worth knowing:

- **It merges.** Your existing `PreToolUse` hooks, your other events and the
  rest of the file are left exactly as they are.
- **It is idempotent**, and matched on the *invocation* rather than the path.
  Re-running with a different `--human` updates the entry; recreating your
  virtualenv and re-running replaces the entry whose executable has moved,
  rather than leaving a dead one beside a live one. A dead entry is
  non-blocking, so two entries would mean one call recorded twice under two
  identities.
- **`--scope local` by default**, the gitignored file. An entry naming one
  person's email in a file the team commits would attribute everybody's
  actions to whoever ran the installer.

`--fail-mode` defaults to `open` in dev and `closed` in prod, per SPEC §12.2.

## Two things to expect

**`AG-IDN-009` fires on QED's own source.** The rule refuses an action that
targets QED's keys, policy or evidence, which is right — QED is changed by an
operator, not by an agent QED is judging. It also means installing the hook
*in the QED checkout itself* denies every edit to `qed/`. That is the rule
working. Use `--scope local` elsewhere, or add an override in your own policy
directory if you are developing QED.

**Reads are recorded.** `Read`, `Glob` and `Grep` are most of what a coding
agent does, so the chain grows with the session: two records per tool call.
That is the point — a call nobody stopped is still a call somebody made — and
retention and purge (SPEC §10.6) are how a long-lived instance keeps it
bounded.

## Codex

Not built. SPEC §12.2 says "implement when API confirmed", and it is not. A
stub that accepted calls and recorded nothing would be worse than its absence,
because `qed doctor` would list an adapter that does nothing.

## Related

- `docs/mcp-proxy.md` — the same kernel, for an MCP server's tools.
- `docs/http-proxy.md` — for everything else the agent reaches over HTTP.
- `docs/assurance-classes.md` — why advisory is recorded as advisory.
- `docs/adr/0008-hook-answers-ask-and-never-allow.md`.
