# F-003 Kanban operator seams

For JEV-enabled boards, worktree dispatch now requires board metadata alongside `jev_mutation_gate`:

```json
{"workspace_preflight":{"upstream_ref":"refs/heads/main","required_paths":["src","tests"]}}
```

Use the actual merged upstream ref and paths for that board. Dispatch checks the linked checkout's registration, branch, upstream ancestry, clean state, and required paths before spawning a worker. Missing metadata or a stale checkout blocks the card for operator repair. The existing `decide-policy` admission and dispatch gates remain mandatory on JEV-enabled boards; no new policy bypass is added.

`kanban block <id> --kind operator_wait <reason>` records a sticky typed wait and emits the existing `blocked` notifier wake event. `kanban operator-wake <id> <reason>` unblocks, dispatches and waits for a new heartbeat. **Credentialed `operator-publish-pr` is disabled:** a worker-controlled worktree can contain Git hooks or local configuration that execute in the operator credential context. Publish using a separately trusted operator checkout, read the exact GitHub head back, then run `kanban operator-bind-pr <id> --pr-url <exact-url> --head-sha <40-hex> <reason>` followed by `kanban operator-continue-pr <id> --pr-url <exact-url> --head-sha <40-hex> <reason>`. The latter records the target comment and durable continuation marker, dispatches, and verifies a new heartbeat. If publication succeeds but binding fails, **do not publish again**: inspect the existing PR and retry `operator-bind-pr` on that exact URL/head, then continue. If continuation fails after binding, inspect the card/run before retrying; never rewrite its immutable target.

These commands are operator-only. They never approve, merge, deploy, enter secrets, or complete a human gate. The board needs its normal notifier subscription for wake delivery; an un-subscribed board still records the typed block but cannot deliver a chat ping.

Fellowship JEV `check-workspace` also accepts `--require-registered --upstream <ref> --require-path <relative>` (repeatable). It remains a separate CLI preflight; Hermes verifies equivalent git invariants locally because the sandboxed policy evaluator cannot read arbitrary host worktrees.

## Exact PR target and credential boundary

Cards using the audited wrappers declare `Repository: ` followed by a backtick-
quoted `owner/repo` in their immutable body. The operator first runs
`hermes kanban operator-bind-pr <id> --pr-url <exact-url> --head-sha <40-hex> "<reason>"`
on ready/todo review and human-merge cards. It reads the PR from GitHub and
records one immutable `pr_target_bound` event matching the card repository,
base repository, branch (if declared), and head. `operator-continue-pr` and
`collect-human-merge` refuse an absent, mismatched, or duplicate binding;
the latter also reads GitHub's actual `merged_by` and exact head. Manual publication
must be followed by binding before continuation. A head move requires a new
card and fresh exact-head gates; a binding cannot be rewritten.

Only an operator process with separately held GitHub credentials may execute
these commands. Worker containers must have **no host CLI/gh credential or
board-database write access**; an environment variable alone is not an
identity boundary. The collector records a real human merge; it does not
perform the merge or supply Bob's approval. Do not enable these commands in a
shared-credential worker runtime.

## Archive authority provisioning (separate host gate)

Archival and human-merge collection deny by default until the operator creates
`~/.hermes/kanban/archive-authority.json` **outside worker mounts**, owned by
that host user with an owner-only directory and `0600` file mode. Example policy
for this lab (substitute only with Bob's explicit approval):

```json
{"authorized_logins":["myorgcibot"],"human_merge_login":"saltybaker"}
```

The file path is derived from the OS account, not `HOME`, `HERMES_HOME`, board
metadata, or caller environment. A malformed, missing, symlinked, writable-by-
others, or non-owner file denies. The authenticated GitHub caller must match the
allowlist, while GitHub's actual `merged_by` must match the separate human login.
Never mount this policy or the operator's GitHub credential into worker containers.
Install and verify this policy only at the separately authorized host cutover.
