---
title: Smart approval reviewer plugins
---

# Smart approval reviewer plugins (new development API)

This branch adds `ctx.register_approval_reviewer(provider)` and
`tools.approval_reviewer.ApprovalReviewer`. This is **newly implemented**, not
an API supported by older releases. A reviewer is trusted native in-process
**authorization-policy code**, not a human approval transport or observer.
No new model tools or main conversation messages are added.

## Explicit selection

The default remains:

```yaml
approvals:
  mode: smart
  reviewer: builtin
  reviewer_timeout: 10
```

Registration/enabling a plugin does not select it. After reviewing the plugin's
own opt-in requirements, an operator can deliberately set
`approvals.reviewer` to its registered name with `hermes config set` in the
intended profile. `builtin` is reserved. `reviewer_timeout` is a positive finite
number at most 30 seconds. A custom provider runs only at the existing smart
shell review boundary. `manual`, `off`, YOLO, unattended policies, existing
human grants and deterministic floors retain their previous behavior.

**Replacement, not cascade:** any non-`builtin` selection suppresses the old
auxiliary judge, including for unavailable registrations, malformed selection,
unsupported actions, abstention, timeout and errors. These use the original
human path, not another model. An explicit custom deny blocks immediately; it
is not automatically answered by, or converted into, a human owner override.
Custom allows confer no session/permanent/category grants. Human fallback
choices retain existing host consent policy.

`approvals.smart_policy` and `auxiliary.approval.*` configure the **builtin**
reviewer only. A custom provider defines its own documented policy/model knobs;
these settings are not translated or silently applied to it.

## Provider contract

Implement the four abstract methods and register an instance:

- `review(action: ShellAction, *, deadline: float) -> ReviewResult`
- `consume(result: ReviewResult, action: ShellAction) -> bool`
- `execution_valid(action: ShellAction) -> bool`
- `release(action: ShellAction) -> None`

`ReviewResult` contains `decision` (`allow`, `deny`, `abstain`), the exact
`action.binding()` digest and a provider-owned receipt dictionary. Consumption
must validate its own distinct, one-use contract. A shadow receipt is not a
permission. Keep lifecycle validity through the spawn check and discard state
on `release`. Calls are synchronous: providers must bound I/O by the supplied
monotonic deadline. Core rejects late results and starts no callback workers.
This is not a kill boundary for hostile or hanging in-process Python code;
only trusted, deadline-cooperative providers are supported. Host-process plugin
isolation refuses this live-object registration rather than importing it into
the parent or pretending its fences cross the wire.

## Exact supported shell surface

The host currently constructs immutable records only for foreground terminal
calls using the **exact builtin POSIX LocalEnvironment**, with a ready session
snapshot, explicit valid session/turn/tool-call IDs, absolute canonical action
cwd and a resolved bash/sh executable. Local subclasses, remote/container/plugin
backends, background/PTY calls, login fallback, execute_code whole scripts,
prepared approvals lacking this context, sudo rewrites, macOS-open rewrites,
compound-background rewrites, oversized snapshots/commands, BASH_ENV/ENV and
exported shell functions in the spawn environment fall back to human approval.
An existing isolated-backend fast path is not widened by this API.

Records bind exact command bytes, command cwd device/inode, base spawn cwd,
shell metadata, actual subprocess-environment digest, wrapper/snapshot bytes
and metadata, environment-object identity, owning profile, process-instance
identity, session route/session/turn/call, request nonce, effective mode and
configuration digest. The process nonce is not hardware attestation. No
original human intent is currently available through this seam: user-role
history, assistant-carried tasks, compaction and bot notices are **not** promoted
to consent. The shell snapshot is bounded untrusted evidence. Environment
values are not sent separately. If force redaction would change the command,
cwd or snapshot, review abstains rather than judging altered text and executing
the original.

After review, core recomputes the record and consumes the provider receipt.
Immediately before the actual local `Popen`, it rechecks the owning record,
provider identity, deadline, cancellation, configuration, actual argv/env and
one-use execution fence. Drift refuses execution without retry or raw proposal
logging; the next call needs fresh approval. Scope exit invalidates copied
worker contexts too. Provider lifecycle hooks must invalidate active calls on
session/turn end and unload.

This is a **live-state** check, not dependency freezing or a new execution
sandbox. Hashes are not locks: filesystem files, symlink targets and executables
can change after the last check or during execution. A provider must state this
TOCTOU limitation honestly and must never manufacture immutable-dependency or
human-ingress evidence. Reviewer-side containment does not contain Hermes'
main action. Protected writes/tool consent, hardline/runtime/sudo/user-deny
floors and existing human consent remain separate and authoritative.
