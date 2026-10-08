# F1c offline isolation and landing candidate

This internal AgentRunway candidate depends on F1a fork PR #1 at
`7d995ca95202771eb66ceeb939cf9d7d0e2baa41`; acceptance remains pending.
This historical candidate is behind the newer F1a fixes. Integrating a corrected
F1a head requires new F1c source/image evidence and exact-head review. F1a evidence
for a different revision does not attest this candidate.
No route, scheduler, login or inference is enabled.

Tier 0 runs `python -I -m clodfarm.tier0`, a closed JSON-lines tool executor,
in an unprivileged Linux container. It receives only its own approved input,
writable output, read-only job policy, read-only task capability and one
read-only Unix-socket directory. Root is read-only, network is disabled,
all capabilities are dropped, privilege escalation is disabled and resource
limits apply. There is no repository, `.git`, auth profile, supervisor state,
other worker mount or Docker socket. AgentRunway's F1c Compose generator defines
the mounts. Each job requires distinct input/output/capability/socket directories;
never bind a common worker parent into Tier 0.

The closed policy requires explicit input approval and SHA256 for each input.
Startup rejects missing/malformed/writable policy and incorrect policy-byte digest.
Docker also enforces a read-only bind. Public inputs must be explicitly sanitized
snapshots. Credential scanning rejects suspicious inputs and does not substitute
for operator approval. Private repository data must not enter public routes.

Recognized tools are `workspace.read`, `workspace.edit`, `task.status`,
`parent_claude.result`, `task.escalate` and optionally `public_web.read`.
File operations use Linux non-following dirfds, reject traversal, links and special
files, bound text size and check input digests. Edits stop when a task waits,
is revoked or has submitted a proposal. No shell, agents, arbitrary MCP,
messaging, Git or administration tool is exposed. The old shell-off farm CLI
exception is removed. Isolation defaults on; only explicit `0`, `false`, `off` or
`no` for `FARM_REQUIRE_ISOLATION` permits legacy execution. Isolation disables daemon dispatch,
raw run-shim persistence and automatic Git landing in the dogfood image.
`FARM_TIER0=1` denies farm CLI and trusted operator entrypoints before state opens.

`authority.py` owns the durable SQLite task/escalation ledger outside worker mounts.
Tokens are random, hashed at rest and scoped to one task/version. New versions
revoke former capabilities and close their open escalations as superseded with
a system reviewer and timestamp; extra identity fields and unknown tools are denied.
Results remain proposals. Persisted/exported metadata contains only closed identity
fields, reason/authority enums and evidence digests. No provider credentials,
request bodies, prompts, file contents, verification output, run environments or
transcripts are persisted by this path. Worker/broker Docker logging is disabled.
Proposal contents remain in private output and the trusted candidate Git tree.

Escalation pauses work. Ordinary questions go to parent Claude; credential, budget,
policy, terms and external-action decisions go to the human inbox.
`python -I -m clodfarm.f1c inbox` is a read-only trusted CLI view. The private manager
UI shows destinations, task/version, evidence, age and dispositions. Acknowledgement
does not resume work. Human dispositions name the operator; parent Claude cannot
decide human authority requests. Workers cannot approve or retry. SQLite records
and stale-socket recovery preserve the queue across broker restart. Version
advancement or revocation closes open items as superseded with a system decision. No external
notifications are sent. Isolation mode locks privacy, hatching/invites and the
legacy planner even for managers.

Trusted commands: `clodfarm.f1c register`, `serve`, `inbox`, `disposition`, `revoke`,
`prepare`, `candidate`, `review`, `land`, `reconcile`. `FARM_AUTHORITY_DB` names an absolute
supervisor-owned database. Registration runs on the trusted host, checks
`--policy-sha256` against immutable policy bytes, and rejects noncanonical or
overlapping host roots. Broker mounts retain those same absolute paths. The broker
uses UID 10002 and socket/output group 10001, distinct from worker UID 10001.
The socket is mode 0660 and output files mode 0640 in group 10001. Host staging
keeps the supervisor directory mode 0700 owned by UID 10002, never worker-readable.
Registration writes a protected token file without
printing it. `prepare` imports explicitly selected proposal files and creates a
commit on current main without executing worker code, Git hooks, pushes or rebases.
Landing requires `FARM_PUSH=0`, nonempty `FARM_VERIFY_CMD`, a clean main checkout
and an accepted **parent Claude** verdict for the exact candidate. The trusted
Claude workflow supplies a JSON artifact with exactly these fields:

```json
{"task":"example","version":1,"candidate":"<SHA256>","reviewer":"parent-claude","reviewer_run":"parent-claude:<independently-checked-run>","accepted":true}
```

Human-triggered import rejects evidence under every registered input/output root,
links and unsafe ownership/modes; the reviewer run reference must differ from the
worker identity. The trusted operator must check that reference against the real
Claude run before import. JSON declarations alone are not authentication. CLI
dispositions similarly require a named operator or checked Claude run via `--actor`.
Host administration is the trust boundary; it is not a worker capability.
Human-triggered import is implemented. Native unattended reviewer execution remains
subject to F1a terms; F1d is required when Codex participates. Codex cannot replace
Claude's verdict. Worker RPC cannot import verdicts. Mission approvals are ignored.
The candidate identity covers task/version, commit, binary diff, current main base,
verification command and pinned verifier image. Missing/rejected/self/stale reviews
fail. Changes, rebases, new main commits or command/image changes require a fresh
candidate and review. Verification reads committed blobs directly, including
`export-ignore` files, rejects links/submodules, and runs in a networkless container
with no Git/auth/state/socket mounts. Its writable build tree is bounded and
output/logs are discarded. Timeout removes only its unique verifier container.
Verification reruns outside the database write transaction; status RPC reads
remain read-only. A short transaction rechecks task, candidate and review before
recording a durable landing intent. A Git ref compare-and-swap rejects concurrent
main changes. Proposal imports reject `.gitattributes`/`.gitmodules`, and configured
host Git filters block landing. Landing is local only. A crash or failed reset
leaves the intent, revokes the token and blocks further landing. `reconcile` checks
a clean main checkout and whether the reviewed commit is an ancestor of main.
It records completion when main contains it; otherwise it retains the proposal,
clears the stale review and requires preparing/reviewing again. It never resets a dirty checkout: an operator must inspect
and repair it separately. Unit tests inject reset failure and a post-reset crash;
the approved-host F2 recovery control remains pending.

```sh
python -m unittest discover -s tests -p 'test_f1c*.py'
python scripts/f1c_desktop_smoke.py --image sha256:<candidate-image-id>
# The actual landing adapter needs native Linux Docker integration:
F1C_SMOKE_IMAGE=sha256:<candidate-image-id> python -m unittest discover -s tests -p test_f1c.py
```

Portable smoke uses direct Docker CLI operations and a unique disposable volume.
Only a synthetic bootstrap runs as root to set ownership. The broker uses UID
10002 and workers UID 10001, sharing only socket/output group 10001; no test
container gets the Docker socket. It checks real tools/RPC,
EROFS mounts, unreachable egress, absent private state/auth/other-worker mounts,
CLI denial, broker restart/inbox/dispositions and invalid policy controls.
Mock-verifier unit tests and synthetic smoke do not establish live acceptance.
F1b must connect approved model transport to this executor and enforce gateway/quota
controls. `public_web.read` currently returns exact preapproved, digest-checked
public snapshots; it has no network or arbitrary URL/query forwarding.
Re-run controls and whole-runtime F1a inventory checks for every accepted revision.
AgentRunway records this candidate separately without replacing F1a runtime fields.

The dogfood workflow checks out the PR head, uses that exact revision as
`FARM_REVISION`, runs both a real failing verifier (`exit 3`) and a passing
command requiring `/workspace/proposal.txt`, and retains the tested image plus
revision/run metadata. AgentRunway pins that CI-produced image instead of
claiming independent apt/pip builds reproduce the same digest. The supported
cross-repository check is dispatched from the private AgentRunway repository:

```sh
gh workflow run farm-foundation.yml --repo PhiBangKimNguyen/AgentRunway \
  --ref <reviewed-AgentRunway-ref> -f validation=f1c \
  -f image_run_id=<successful-fork-image-run>
```

Run CI only after the PR is ready and Claude approves its exact current head.
The private caller can read AgentRunway; the fork token cannot. AgentRunway's
workflow binds the tested config digest to the exported OCI manifest digest and
uses the containerd image store. It reproduces committed Compose and exercises
host prepare/candidate/land without a scheduler, login, model call or notification.
A successful run records both exact heads; it does not accept live terms/host gates.
The removed fork dispatch failed SHA validation in run 37589362934 and private
checkout in run 37589427465. Neither is passing or billing-blocked evidence.
