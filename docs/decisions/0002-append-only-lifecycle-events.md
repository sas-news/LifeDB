# ADR 0002: Append-only lifecycle events and Canon transactions

Status: accepted for v0.2 design

## Context

LifeDB v0.1 places payload availability, retention, and representations inside a
sealed Evidence record while also declaring that the record must never change.
Eviction, extraction, restoration, and correction necessarily happen after
capture, so those two requirements cannot both hold if current state is stored
in the base record.

The Claim model similarly stores a mutable lifecycle state and one
`observed_at` timestamp. That can describe current state but cannot reliably
answer what Canon accepted at an earlier transaction time. Git can help review
Markdown changes, but Git is optional, rewriteable, and does not by itself cover
Evidence or object lifecycle.

Finally, a bare Claim-to-Evidence UUID does not state whether the Claim depends
on raw bytes, an extracted representation, or only the observation envelope.
Treating every citation as a raw-byte pin defeats selective retention; treating
none as a pin risks destroying required support.

## Decision

LifeDB will keep capture facts immutable during normal operation and represent
later state changes as ordered immutable events. Canon changes will be committed
as transactions containing durable before/after snapshots and an authenticated
actor.

Owner-authorized erasure is an explicit destructive exception. Append-only is an
operational integrity rule, not a restriction on the owner's right to remove
data.

## Evidence capture and lifecycle

An Evidence capture record describes state at capture and is sealed once. Its
payload fields do not claim to be the current availability state forever.

Later changes are separate lifecycle events. The v0.2 event vocabulary includes
at least:

- `representation.added`;
- `retention.changed`;
- `hold.placed` and `hold.released`;
- `payload.eviction-proposed` and `payload.evicted`;
- `payload.missing-observed` and `payload.restored`;
- `metadata.corrected` without removal of the original metadata;
- `erasure.authorized` and `erasure.executed`, when a surviving receipt is
  allowed by the erasure scope.

Each event contains:

- a UUIDv7 event ID;
- the target Evidence ID and, where applicable, object digest;
- a server-assigned monotonically increasing vault sequence;
- a timestamp with explicit offset;
- an authenticated actor;
- an operation and operation-specific data;
- a human-readable reason;
- the policy identifier and version when policy caused the action;
- an idempotency key for replayable external requests when applicable.

A `representation.added` event also records its role, media type, object digest,
producer and version, creation time, and derivation source. Representation bytes
are immutable content-addressed objects.

The reference v0.2 implementation supports the capture, representation,
retention, hold, payload, Candidate, and Canon transaction paths it validates;
owner-erasure events below describe the future destructive boundary and are not
an implemented erasure API.

Runtime code derives the effective Evidence view by folding the capture record
and valid lifecycle events in vault-sequence order. Wall-clock timestamps are
informational and never resolve event ordering. Invalid transitions remain
visible validation errors.

## Claim evidence requirements

Claim Evidence references become structured edges:

```yaml
evidence:
  - id: 019d1255-7d6a-7e43-92bd-0f137f516005
    requires: raw
  - id: 019d1255-7d6a-7e43-92bd-0f137f516006
    requires: representation:ocr
  - id: 019d1255-7d6a-7e43-92bd-0f137f516007
    requires: record-only
```

The values mean:

- `raw`: the captured payload object must be present;
- `representation:<role>`: at least one policy-selected, durable representation
  with that role must be present;
- `record-only`: only the Evidence capture record is required.

New v0.2 Claims must state `requires`; there is no implicit default. During
migration, an old bare Evidence ID is conservatively converted to `raw` until the
owner or a reviewed policy narrows it.

Retention is evaluated per object across all current accepted Claim edges,
Evidence references, explicit holds, and policy constraints. Historical Canon
snapshots do not remain live raw-byte pins merely because they contain an old
`requires: raw` edge. An explicit archival or legal hold may still pin them.

If a required payload or representation is unavailable, the Claim is not
silently deleted. Validation and Context generation report the broken support.
Owner-authorized erasure may intentionally create that condition and may redact
the affected Claim or transaction according to the approved scope.

## Canon transactions

Every accepted Canon change is associated with one transaction. A transaction
contains:

- a UUIDv7 transaction ID and vault sequence;
- preparation and commit times;
- the authenticated actor and producing process or model version when known;
- a reason and optional input Evidence or Candidate IDs;
- for every affected Canon document, its stable semantic ID and durable before
  and after snapshot bytes, with hashes;
- explicit absence for document creation or deletion;
- the applicable schema and policy versions.

Hashes verify snapshot bytes but are not substitutes for snapshots. Snapshot
bytes are durable and included in backup and erasure traversal.

The writer stages all after-snapshots, preserves before-snapshots, validates the
resulting Canon graph, and records transaction preparation under the
single-writer lock. Per-file publication is atomic. A final immutable commit
event makes the transaction part of Canon history. Recovery either completes or
reverts an interrupted prepared transaction from its snapshots. Only committed
transactions participate in a future as-of reconstruction; the reference does
not expose a general as-of API.

Validation expects the visible `canon/` tree to match the latest committed
transaction. A direct manual edit is allowed as an authoring action, but it is
uncommitted drift until LifeDB captures and validates it as a transaction.
Validators report drift; the retrieval index still parses valid live Canon files,
including such out-of-band edits.

An eventual as-of view can fold committed transactions through a requested vault
sequence. The v0.2 reference does not expose a general as-of read API. A rollback
creates a new compensating transaction whose after-snapshots restore selected
prior content. Neither rollback nor ordinary correction deletes the transactions
being reversed.

Git remains optional. When enabled, a Canon transaction may reference a Git
commit, but correctness, history, and rollback do not depend on that commit.

## Context authorization and rendering

The Context Builder uses the effective Evidence view and the live Canon files
that the runtime index parses during rebuild. Valid manual or out-of-band Canon
edits are therefore searchable; Canon transactions audit managed changes, and
validation detects drift from the latest committed snapshot. Retrieval does not
use transaction snapshots as its sole Canon source or reconstruct an as-of
view.

In the normative full-deployment design, authorization may combine authenticated
client policy, operation, destination, purpose, and effective sensitivity.
The v0.2 reference instead authenticates one owner Bearer token, records
server-fixed principal/destination/purpose labels, and applies its global
server sensitivity ceiling and Context budgets. It has no per-client operation
scopes or destination/purpose allowlists; request values may only narrow
sensitivity and budgets.

Every Context build enforces total and per-layer budgets. Its result records one
global durable event sequence, the runtime index's indexed sequence and `dirty`
status, truncation, and degraded status in its pack-level watermark. It does not
attach separate Canon-transaction or Evidence-lifecycle revisions to each
result or item. Retrieved content is rendered within explicit untrusted-data
boundaries and cannot grant permissions or override host instructions.

## Integrity and authenticity

SHA-256 content addressing verifies that available bytes match a known digest.
It does not authenticate an actor, acquisition path, timestamp, or factual
claim. Producer fields are trustworthy only to the extent that the service
authenticated and assigned them. Authenticity mechanisms may be added without
changing the lifecycle model.

## Erasure exception

An authenticated owner may authorize erasure of an exact scope after an impact
preview. The operation traverses captures, lifecycle events, objects,
representations, Canon snapshots, runtime projections, and known backups.

Erasure may make as-of reconstruction or rollback intentionally incomplete. A
minimal receipt may state that an erasure occurred only when doing so does not
violate the requested scope. No automated eviction or ordinary client operation
has this authority.

## Consequences

- Evidence records no longer contradict their own sealed status.
- Payload and representation state can be reconstructed and audited.
- Canon supports durable snapshot history and rollback without requiring Git;
  general as-of reads remain future work.
- Retention can distinguish semantic dependence from a mere citation.
- More durable records and validation logic are required.
- Event ordering and single-writer recovery become part of the core format.
- Owner erasure is honest about the resulting loss of history.

## Rejected alternatives

### Mutate the sealed Evidence record

Rejected because it destroys the capture-time statement, makes races hard to
audit, and contradicts normal-operation immutability.

### Use Git as the only Canon history

Rejected because Git is optional, does not cover all durable stores, and can be
rewritten or omitted from a backup.

### Pin raw bytes for every Evidence citation

Rejected because common Canon facts would indefinitely pin large, reproducible
web and passive-capture payloads.

### Let the caller choose its authorization ceiling

Rejected because a request is not an authority source.

### Treat a matching hash as source authentication

Rejected because a digest establishes byte equality, not origin or truth.

## v0.2 implementation boundary

Version 0.2 implements the durable event and transaction formats, effective-view
projection, validation, authorized Context rendering, and manual lifecycle
actions including retention preview/apply/recovery. Owner-erasure preview/apply,
general as-of reads, automatic eviction, AI reconciliation, extraction
pipelines, multi-writer synchronization, learned retrieval, and signature
infrastructure remain outside the v0.2 core.
