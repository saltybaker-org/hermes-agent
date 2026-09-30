# F-003 Kanban operator seams

For JEV-enabled boards, worktree dispatch now requires board metadata alongside `jev_mutation_gate`:

```json
{"workspace_preflight":{"upstream_ref":"refs/heads/main","required_paths":["src","tests"]}}
```

Use the actual merged upstream ref and paths for that board. Dispatch checks the linked checkout's registration, branch, upstream ancestry, clean state, and required paths before spawning a worker. Missing metadata or a stale checkout blocks the card for operator repair. The existing `decide-policy` admission and dispatch gates remain mandatory on JEV-enabled boards; no new policy bypass is added.

`kanban block <id> --kind operator_wait <reason>` records a sticky typed wait and emits the existing `blocked` notifier wake event. `kanban operator-wake <id> <reason>` unblocks, dispatches and waits for a new heartbeat. `kanban operator-continue-pr <id> --pr-url <exact-url> --head-sha <40-hex> <reason>` verifies the open PR at its exact head, records the target comment and durable continuation marker, dispatches, and verifies a new heartbeat. `kanban operator-publish-pr <id> --repo <card-worktree> --remote <remote> --base <base> <reason>` additionally checks a clean exact branch, refuses an existing open PR, pushes, reads the remote head, creates the PR, and uses the same continuation path. Failures after push or PR creation retain external state: inspect before retrying; use `operator-continue-pr` rather than creating a duplicate.

These commands are operator-only. They never approve, merge, deploy, enter secrets, or complete a human gate. The board needs its normal notifier subscription for wake delivery; an un-subscribed board still records the typed block but cannot deliver a chat ping.

Fellowship JEV `check-workspace` also accepts `--require-registered --upstream <ref> --require-path <relative>` (repeatable). It remains a separate CLI preflight; Hermes verifies equivalent git invariants locally because the sandboxed policy evaluator cannot read arbitrary host worktrees.
