# LifeDB Durable Format and Canon Specification 0.2

Status: Draft executable specification  
Software release line: 0.2.x  
OKF target: 0.2  
Schema dialect: JSON Schema 2020-12

## 1. Purpose

LifeDB represents a person's accepted current model and the observations from
which that model was formed. Its durable state remains usable when a particular
database, model provider, agent host, container image, or application ceases to
exist.

LifeDB distinguishes four stores:

1. **Canon**: the owner's accepted current semantic model in `canon/`.
2. **Evidence**: immutable capture records and append-only observation and
   lifecycle events in `evidence/`.
3. **Objects**: policy-retained raw, derived, and Canon snapshot bytes in
   `objects/`.
4. **Runtime**: disposable indexes, effective views, and caches in `runtime/`.

Canon is fallible and revisable. Evidence establishes what LifeDB recorded, not
that a source was honest or that an assertion is objectively true. A digest
establishes byte integrity, not authenticity. The normative philosophy and
security boundaries are described in `docs/philosophy.md` and
`docs/threat-model.md`.

## 2. Normative language

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

The durable format version is written as `"0.2"`. Software implementing this
specification uses the `0.2.x` release line. API major version `/v1` is versioned
independently from the durable format.

## 3. Core invariants

1. Canon documents MUST remain readable as UTF-8 Markdown without LifeDB.
2. Canon documents MUST have parseable YAML frontmatter and an OKF `type`.
3. Every LifeDB semantic object MUST have a stable UUIDv7 in `x-lifedb.id`.
4. Stable identity MUST NOT depend on a filename, directory path, product name,
   or agent host.
5. A sealed capture or lifecycle event MUST NOT be edited during normal
   operation.
6. Current payload state and representations MUST be projected from an immutable
   capture and its ordered lifecycle events.
7. A semantic correction MUST create a new Claim and supersede, retract, or
   dispute the old Claim.
8. Every accepted Canon mutation MUST use a prepared/committed transaction with
   durable before/after snapshots and an authenticated actor.
9. Runtime state MUST be reconstructable without network access to an AI model.
10. Embeddings, retrieval scores, and Context Packs MUST NOT be authoritative
    data.
11. Every AI-generated durable assertion or representation MUST retain
    provenance, but provenance MUST NOT be presented as source authenticity.
12. Every Claim-to-Evidence edge MUST state whether it requires raw bytes, a
    named representation role, or only the Evidence record.
13. Credentials, private keys, passwords, and authentication tokens MUST NOT be
    deliberately stored in the vault.
14. Unknown fields MUST be preserved by round-tripping durable-data tools.
15. Authorization, sensitivity limits, and Context budgets MUST be resolved by
    the server; client input may narrow but MUST NOT widen them.
16. Normal operation is append-only, but an exact, explicitly confirmed,
    owner-authorized erasure takes priority over historical completeness.

## 4. Vault layout

```text
vault/
├── vault.json
├── canon/
│   ├── index.md
│   ├── core/
│   ├── self/
│   ├── entities/
│   ├── projects/
│   ├── topics/
│   ├── goals/
│   ├── decisions/
│   ├── patterns/
│   ├── procedures/
│   └── conflicts/
├── evidence/
│   ├── <source>/<year>/<month>/<day>/<evidence-id>.json
│   └── _events/<category>/<year>/<month>/<day>/<event-id>.json
├── objects/
│   └── sha256/<first-2>/<next-2>/<digest>
├── quarantine/
├── policies/
├── schemas/
├── migrations/
└── runtime/
```

Time-based directories are physical partitions, not semantic identity. Canon
paths are topic-oriented human-facing addresses. Snapshot objects needed by a
prepared or committed Canon transaction are durable even though they live in the
shared Object Store.

In the v0.2 reference, `quarantine/` is primarily staging for a prepared
retention transaction. It is not yet the capture landing zone for passive
collectors; such collectors are outside the implementation boundary.

## 5. Identifiers and ordering

### 5.1 Stable IDs

Vaults, semantic objects, Claims, Evidence captures, events, Conflicts,
Candidates, Canon transactions, and Context Packs use UUID version 7 as defined
by RFC 9562. The canonical text form is lowercase with hyphens.

UUIDs are stored bare in structured data. APIs MAY expose resolvable URIs:

```text
lifedb://<vault-id>/canon/<uuid>
lifedb://<vault-id>/evidence/<uuid>
lifedb://<vault-id>/claim/<uuid>
lifedb://<vault-id>/object/sha256/<digest>
```

`vault-id` is generated once by `lifedb init`. Export and merge tools MUST retain
the origin vault ID when bare IDs leave one vault.

### 5.2 Paths

Moving a Canon file MUST NOT change its semantic ID or Claim IDs. LifeDB clients
resolve structured references by UUID. A move can still break ordinary OKF
Markdown links, so a conforming mover MUST update links or leave a redirecting
stub at the old path.

### 5.3 Durable event order

Each v0.2 event receives a server-assigned, vault-global integer `sequence`
starting at 1. `previous_event` is the UUIDv7 of the immediately preceding event,
or `null` for sequence 1. Sequence, not a wall-clock timestamp or UUID sort order,
defines the fold order.

Under normal operation, sequences are unique and contiguous and every
`previous_event` resolves. An owner-authorized erasure may intentionally create
a documented history boundary.

## 6. OKF v0.2 compatibility

`canon/` is an OKF v0.2 knowledge bundle. The compatibility reference is the
[OKF v0.2 specification](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md).
Its root `index.md` SHOULD declare:

```yaml
---
okf_version: "0.2"
---
```

OKF v0.2 requires only `type` on a concept document. LifeDB defines a stricter
profile by additionally requiring `x-lifedb` on LifeDB Canon concepts. Ordinary
OKF consumers can ignore the extension and still read the Markdown.

LifeDB uses OKF fields such as `description`, `resource`, `tags`, `sources`,
`generated`, `verified`, `status`, and `stale_after` instead of duplicating them
inside `x-lifedb`.

Within an OKF `sources` entry, `resource` is required and `id` is optional. A
LifeDB producer SHOULD add `id` when Markdown footnotes or another field need a
stable per-source attribution key, but MUST NOT reject an otherwise valid OKF
source merely because `id` is absent. OKF Concept IDs remain bundle-relative
paths; `x-lifedb.id` supplies LifeDB's path-independent identity.

Unknown OKF types and unknown frontmatter fields MUST be tolerated and preserved.
An OKF consumer that does not understand `x-lifedb` must still receive ordinary
readable Markdown/YAML after round-tripping.

## 7. Canon documents

Every non-reserved Markdown file under `canon/` has YAML frontmatter followed by
ordinary Markdown. `index.md` and `log.md` follow OKF conventions.

A minimal LifeDB Canon document is:

```yaml
---
type: Entity
title: Zed
x-lifedb:
  schema: "0.2"
  id: 019d1255-7d6a-7e43-92bd-0f137f516005
  kind: software
  sensitivity: personal
  claims: []
---
```

The initial vocabulary is:

- `Profile`: identity, values, preferences, environment, and abilities;
- `Entity`: a person, organization, product, place, work, or other referent;
- `Project`: an undertaking with lifecycle and outcomes;
- `Topic`: an area of sustained knowledge;
- `Goal`: a desired future state with completion criteria;
- `Decision`: alternatives, reasoning, choice, and consequences;
- `Pattern`: a repeated tendency inferred across Evidence;
- `Procedure`: reusable procedural knowledge;
- `Conflict`: an unresolved or intentionally accepted contradiction among
  Claims.

This vocabulary is extensible. A Consumer MUST show an unknown type as a generic
concept rather than dropping it.

## 8. Claims

A Claim is an atomic, independently identified assertion embedded in the
`x-lifedb.claims` array of the document that describes its subject. Generated
views MAY show it elsewhere but MUST NOT create a second authoritative copy.

Required Claim fields are:

- `id`: Claim UUIDv7;
- `subject`: semantic UUIDv7;
- `predicate`: extensible lowercase predicate name;
- `object`: exactly one typed value;
- `statement`: a human-readable assertion meaningful without a predicate
  registry;
- `basis`: `declared`, `observed`, `inferred`, `imported`, or `computed`;
- `certainty`: `confirmed`, `probable`, `tentative`, or `unknown`;
- `state`: `active`, `superseded`, `retracted`, or `disputed`;
- `observed_at`: when LifeDB learned or confirmed the assertion;
- `evidence`: one or more typed Evidence edges.

Core predicates use the `lifedb.` prefix. Private extensions SHOULD use a stable
producer namespace. Unknown predicates MUST be retained and displayed using
`statement`.

### 8.1 Typed object values

`object` contains exactly one of:

- `ref`: UUIDv7 of another semantic object;
- `text`: UTF-8 string;
- `boolean`: JSON boolean;
- `number`: finite JSON number, with an optional `unit` sibling;
- `date`: RFC 3339 full-date;
- `datetime`: RFC 3339 timestamp with explicit offset;
- `uri`: absolute URI;
- `json`: arbitrary finite JSON data for forward compatibility.

### 8.2 Typed Evidence edges

New v0.2 Claims represent each Evidence reference as:

```yaml
evidence:
  - id: 019d1255-7d6a-7e43-92bd-0f137f516006
    requires: raw
  - id: 019d1255-7d6a-7e43-92bd-0f137f516007
    requires: representation:ocr
  - id: 019d1255-7d6a-7e43-92bd-0f137f516008
    requires: record-only
```

The requirement means:

- `raw`: the effective Evidence payload must be `present` and its object must
  verify;
- `representation:<role>`: at least one retained, verifying representation with
  exactly that non-empty role must be available;
- `record-only`: the sealed capture record is sufficient.

A new v0.2 writer MUST NOT omit `requires`. For compatibility, a bare Evidence
UUID from v0.1 is interpreted conservatively as `raw` and MUST be rewritten to
the explicit mapping when migrated or promoted.

The requirement describes minimum retained support, not evidential strength or
source authenticity. A currently unsatisfied requirement is a validation error
and MUST be reported in Context rather than silently ignored.

### 8.3 Certainty and basis

`basis` describes how an assertion was obtained. `certainty` describes how
directly available Evidence supports the exact assertion. Neither is a numerical
probability. For example, `declared + confirmed` confirms that the declaration
was recorded; it does not independently prove the declarant's statement.

Numeric model confidence MUST NOT be stored in Canon. It MAY appear in a pending
Candidate or disposable runtime record.

### 8.4 Valid and transaction time

`valid.from` and exclusive `valid.until` describe when the assertion applies in
the represented world. Bounds may be RFC 3339 dates or timestamps with explicit
offsets. When both are present they MUST use comparable precision and `from`
MUST be earlier than `until`. A missing bound means unknown, not a claim of
infinite validity.

`observed_at` is knowledge-observation time, not Canon transaction time.
Transaction time is the sequence and commit time of the Canon transaction that
accepted, superseded, disputed, or retracted the Claim. A future as-of view would
use committed transaction sequence; the v0.2 reference exposes no general as-of
API.

### 8.5 Supersession and conflicts

Changing the meaning of a Claim requires a new Claim ID. A new Claim lists old
Claim IDs in `supersedes`; old Claims move to `superseded` and list the new ID in
`superseded_by` in the same Canon transaction. Retraction and dispute are also
transactional changes.

A persistent contradiction involving multiple Claims is represented by a
`Conflict` document. Its state is `open`, `resolved`, or `accepted`; `accepted`
means ambiguity is intentionally retained. Retrieval MUST NOT arbitrarily choose
one disputed Claim as uncontested current fact.

## 9. Provenance and sensitivity

Document-level provenance uses OKF `sources`, `generated`, and `verified`.
Claim-level provenance uses typed Evidence edges. Markdown footnotes SHOULD use a
matching `sources[].id` where one is present.

AI-produced durable material records the producing actor, model and process
version when known. A reconciler MUST NOT label content human-verified merely
because the underlying statement originated with the owner.

The sensitivity levels are:

- `public`;
- `personal`, the default for the v0.2 reference server profile and an
  available default for a full-deployment client policy;
- `sensitive`, requiring explicit deployment-policy authorization (a full
  deployment may bind this to client and purpose; the reference uses its
  server sensitivity ceiling);
- `restricted`, confined to an approved local execution boundary.

A Claim may raise its document sensitivity but cannot lower it. Returned
fragments use the maximum effective sensitivity of document, Claim, Evidence,
representation, and applicable policy. Authorization is enforced before
retrieval and rendering.

## 10. Evidence capture records

New captures use schema `"0.2"`, `record_type: "capture"`, and validate against
`schemas/evidence-record.schema.json`. A capture includes:

- UUIDv7 `id`;
- `captured_at` and `ingested_at` with explicit offsets;
- `source.kind` and optional URI, account, device, metadata, and `external_id`;
- content media type, byte size, and bare lowercase SHA-256 digest;
- initial payload state and retention class;
- capture-time representations, normally an empty list;
- sensitivity and producer;
- `sealed: true`;
- `integrity` in the form `sha256:<64 lowercase hexadecimal characters>`.

`integrity` is computed over the deterministic canonical UTF-8 JSON form of the
record with the `integrity` member omitted. It detects later record modification;
it is not a signature and does not authenticate the producer or source.

The capture file is atomically published only after every referenced retained
object has been written and verified. Normal operations never edit it.

### 10.1 Idempotent source events

Collectors and replayable imports SHOULD provide `source.external_id`. The
idempotency key is scoped by the complete source envelope:
`(source.kind, source.uri, source.account, source.device, source.external_id)`.
For compatibility, legacy `source.metadata.account` and
`source.metadata.device` values are promoted to the corresponding top-level
source fields before this key is evaluated:

- a replay with the same content digest returns the existing capture;
- reuse with a different digest fails as a conflict;
- absence of `external_id` creates a distinct capture even when bytes deduplicate.

An external ID is provenance metadata, not authentication of the external
system.

### 10.2 Reference-only capture

`retention: reference-only` requires an absolute `source.uri`. LifeDB records the
observed content metadata and digest but MUST NOT store the original payload
object. Its initial payload state is `external` and `payload.object` is absent.

Reference-only does not promise that the URI remains retrievable or unchanged.
It is invalid for irreplaceable material unless the owner explicitly accepts
that loss risk.

## 11. Immutable lifecycle events

Later representations and payload changes are recorded as schema `"0.2"`,
`record_type: "event"` records beneath `evidence/_events/`. Each event includes:

- UUIDv7 `id` and non-empty `event_type`;
- vault-global positive integer `sequence`;
- `previous_event`, the immediately preceding Event ID or `null`;
- `recorded_at` with explicit offset;
- authenticated or process-assigned `actor`;
- optional UUIDv7 `target` and operation-specific `data`;
- sensitivity, `sealed: true`, and `integrity` as `sha256:<digest>`.

Lifecycle events targeting an Evidence capture require `target`. Canon and
Candidate transactions use the same ordered event envelope with their own UUIDv7
targets.

Canonical payload lifecycle names are:

- `representation.added`;
- `retention.changed`;
- `hold.placed` and `hold.released`;
- `payload.eviction-proposed` and `payload.evicted`;
- `payload.missing-observed` and `payload.restored`;
- `payload.redacted`.

A representation event records role, object digest, media type, creation time,
producer and version, and derivation source. A v0.2 reader MAY accept the legacy
hyphenated aliases `representation-added`, `payload-evicted`,
`payload-restored`, and `payload-redacted`; a v0.2 writer SHOULD emit dotted
names.

An effective Evidence view is the immutable capture folded with valid target
events in `sequence` order. It is a runtime projection. Eviction, restoration,
redaction, or representation creation MUST NOT rewrite the capture JSON.

## 12. Object storage

Raw, derived, and Canon snapshot bytes use SHA-256 content addressing:

```text
objects/sha256/ab/cd/abcdef...
```

Objects are written atomically, their digest is verified before publication,
and identical bytes are stored once. Metadata, sensitivity, retention, and holds
belong to references and events rather than filenames.

Because one digest can have references with different policies, retention uses
the strongest current Claim requirement, transaction-snapshot requirement,
explicit hold, and policy across all references. Direct access to a digest is
not authorization to read its bytes.

The v0.2 retention classes are:

- `pinned`: excluded from ordinary eviction proposals;
- `durable`: retained until an explicit reviewed policy change;
- `grace`: eligible for a proposal after its grace condition;
- `derivative-only`: raw bytes may be proposed only after required durable
  representations exist;
- `reference-only`: URI and metadata are retained and original bytes were never
  stored.

Retention execution is specified in `docs/retention.md`. Version 0.2 never
performs an automatic deletion: it generates a preview and requires an explicit
apply against that exact, revalidated preview.

## 13. Canon transactions and rollback

Every managed Canon change uses ordered events and durable snapshots. A
transaction includes UUIDv7 transaction ID, actor, operation, affected semantic
document and path, input Candidate and Evidence IDs where applicable, and
`sha256:` references to exact before and after Markdown bytes.

The transaction protocol is:

1. acquire the single-writer Canon lock;
2. read the current document and store verifying before/after snapshot objects;
3. validate the proposed Canon graph and all typed Evidence requirements;
4. append `canon.change-prepared`;
5. atomically publish the after snapshot using a compare-and-swap check against
   the before digest;
6. append `canon.change-committed`, or restore the before snapshot and append
   `canon.change-aborted` after failure.

Only committed transactions affect accepted transaction history. Prepared-only
transactions are recovery work, not accepted changes. Snapshot objects needed by
prepared and committed transactions MUST NOT be evicted by ordinary retention.

Rollback uses the same protocol with `canon.rollback-prepared` and
`canon.rollback-committed`. It verifies that current bytes still match the source
transaction's after snapshot and creates a compensating transaction; it never
deletes the transaction being reversed.

Transaction snapshots provide durable Canon history and the source material for
rollback. The v0.2 reference does not expose a general as-of Canon view or an
API that selects state through an arbitrary requested durable sequence. Git
commits MAY be attached for review, but Git is not required for transaction
history or rollback.

## 14. Candidate knowledge and reconciliation

Ingestion never writes Canon directly. Version 0.2 provides an explicit manual
Candidate workflow:

1. create a Candidate for a target Canon document with a validated Claim
   proposal and typed Evidence edges;
2. inspect pending Candidates;
3. explicitly reject one with actor and reason, or promote one;
4. validate semantic references, Evidence requirements, sensitivity, temporal
   fields, and supersession;
5. promote through a prepared/committed Canon transaction;
6. retain Candidate creation and terminal state as immutable events.

Candidate state is `pending`, `promoted`, or `rejected` and is projected from
events. A failed promotion leaves the Candidate pending after compensation.

Automatic AI extraction, automatic Candidate creation, automatic promotion, and
background reconciliation are outside v0.2. An AI-authored proposal may enter
the manual workflow only with producer provenance and an explicit actor action.

## 15. Context contract

`context.build` automatically runs authorized lexical retrieval when called. A
fully integrated host calls it before every user turn; relying on a model to
choose a memory tool is degraded operation. The v0.2 service provides the
Context Builder contract but does not provide universal host hooks or MCP.

Context Packs contain:

1. `core`: selected accepted high-impact context;
2. `continuity`: a heuristic selection of active-project and open-loop Canon,
   plus recent session- or workspace-matching Evidence when routing labels are
   supplied;
3. `relevant`: automatically retrieved Canon, Claim, Evidence, or retained
   textual-representation snippets;
4. `evidence_handles`: authorized references for separately controlled
   expansion.

The v0.2 reference's authenticated server profile supplies maximum sensitivity
and one global set of character budgets for all authenticated requests. A full
deployment MAY maintain distinct profiles per client. Defaults are:

```text
budget_chars      24000
core_chars         8000
continuity_chars   4000
relevant_chars    12000
```

The server reduces layer budgets as needed so their sum does not exceed the
applied total. Request values can only reduce server limits. Authorization is
applied before ranking, snippet creation, and expansion.

Every Context Pack reports:

```json
{
  "watermark": {
    "durable_sequence": 42,
    "indexed_sequence": 42,
    "dirty": false
  }
}
```

A dirty or lagging projection is rebuilt before use when possible; otherwise the
pack states that retrieval is degraded. Rendered snippets use escaped,
unambiguous untrusted-data delimiters. Retrieved material cannot grant tool or
secret access or override host instructions. Full details are in
`docs/context-protocol.md`.

## 16. Runtime projections

Runtime systems may include SQLite lexical indexes, effective Evidence views,
transaction catalogs, and caches. Every projection declares the durable schema
versions and highest durable event sequence it includes.

Rebuild indexes Canon prose and structured Claims, readable capture payloads,
and retained textual representations. It must work without the models that
created durable representations. A write marks the relevant projection dirty.

Deleting all of `runtime/` followed by rebuild MUST preserve accepted knowledge,
event order, searchability, and authorization behavior.

The reference CLI exposes `lifedb runtime reset --confirm DELETE-RUNTIME` for
this disposable-state deletion. It is an explicit guarded operation, targets
only the initialized vault's `runtime/`, and MUST be run with the server stopped
to avoid concurrent writers. It refuses filesystem roots, home/repository
roots, symlinked or non-directory targets, and uninitialized vaults.

The reference SQLite projection includes structured `concepts`, `claims`,
`claim_evidence`, and `claim_edges` tables. They preserve queryable graph-shaped
relationships during rebuild, but the v0.2 API does not expose graph traversal,
graph ranking, or graph search. Vector stores, embeddings, and learned rerankers
are not part of v0.2 conformance and are not implemented by the reference
software.

These SQLite tables are implemented projections, not an unimplemented graph
feature. Consumers that need graph traversal or ranking must build that behavior
above the exposed structured tables.

## 17. Authorization and deployment

The reference HTTP server authenticates every `/v1/*` request with
`Authorization: Bearer ...` using `LIFEDB_API_TOKEN`. The token MUST be supplied
through the process environment or an external secret mechanism and MUST NOT be
written to the vault. `/health` is the only unauthenticated endpoint.

`LIFEDB_SENSITIVITY_CEILING` sets the server-profile maximum and defaults to
`personal`. A request sensitivity value only narrows that maximum. `client` and
`actor` strings supplied in request bodies are labels, not authentication.
`LIFEDB_INGEST_SENSITIVITY_FLOOR` sets the minimum sensitivity for HTTP capture;
the caller may raise it but cannot lower it. Context budgets are additionally
bounded by the validated durable context policy.

The default deployment binds only to localhost. Authentication is still required
because other local processes are not automatically trusted. Remote exposure
requires an approved TLS endpoint, reverse proxy, destination policy, rate and
quota controls, free-space monitoring, and an explicit destination-disclosure
review. The reference has a single owner Bearer token and does not provide
operation-level scopes within that token; it does not enforce per-source quotas,
request rates, or free-space thresholds.

Docker is replaceable. The vault is bind-mounted from a host-visible backed-up
path; durable data MUST NOT exist only in a container layer or anonymous volume.

## 18. Retention and owner erasure

The reference CLI implements ordinary retention as a manual two-phase operation:

1. `preview` resolves exact objects, current typed Claim requirements, holds,
   representations, policy version, affected Evidence, and estimated bytes;
2. `apply` requires explicit confirmation of that exact preview and revalidates
   it under the writer lock before changing anything.

There is no scheduled or automatic apply in v0.2. A stale preview fails closed.
Successful lifecycle changes append immutable events and dirty runtime
projections.

The available commands are `lifedb retention preview`,
`lifedb retention apply <plan-id> --confirm 'sha256:<confirmation>' --actor
<actor>`, and `lifedb retention recover`. Preview and recover are executable
commands; apply requires the exact confirmation returned by that preview.

Owner-authorized erasure is separate from retention eviction. It requires strong
owner authorization, a complete impact preview, exact confirmation, and
traversal of captures, events, raw objects, representations, Canon snapshots,
and runtime copies in scope. It may intentionally make as-of history or rollback
incomplete.

LifeDB reports known backup impact but cannot erase offline or provider-managed
backups itself. Backup inventory, expiry, deletion, and preventing restoration of
erased data remain deployment-operator responsibilities.

The durable backup set is `vault.json`, `canon/`, `evidence/`, `objects/`,
`policies/`, `schemas/`, and `migrations/`. While a retention transaction is
prepared or in flight, `quarantine/` is also required in the consistent backup
set. `runtime/` is disposable and is rebuilt rather than backed up.

## 19. Versioning and migration

Readers accept v0.1 durable records only through documented compatibility paths.
Writers emit v0.2. Migration is append-only or works on a verified copy before
replacement and includes:

1. source and target schema identifiers;
2. deterministic migration code where possible;
3. rollback instructions;
4. fixtures from the previous format;
5. unknown-field round-trip tests;
6. disaster-recovery tests.

Specific compatibility rules include:

- a v0.1 bare Claim Evidence UUID becomes `{id: <uuid>, requires: raw}`;
- a v0.1 sealed Evidence record is a legacy capture; later changes are v0.2
  events rather than edits;
- a v0.2 `reference-only` capture requires a URI and has no stored payload
  object;
- existing Canon content receives a baseline snapshot before managed changes.

## 20. v0.2 scope and conformance

The v0.2 executable core includes durable capture and lifecycle events, manual
Candidate reconciliation, transactional Canon mutation and rollback, explicit
ordinary-retention preview/apply/recovery, lexical and structured SQLite
rebuild, server-authorized Context Packs, and disaster recovery. Owner-erasure
semantics are specified in this document but owner-erasure preview/apply is not
implemented by the reference software.

A conforming v0.2 vault and implementation satisfy all of the following:

1. vault, Canon, Capture, Event, and Context data validate against their v0.2
   schemas while preserving unknown fields;
2. Canon is a valid LifeDB profile of OKF v0.2 and stable UUIDs are unique;
3. capture and event integrity values verify, event sequences are valid, and
   effective Evidence folds deterministically;
4. present raw and representation objects exist and match their paths, while
   valid reference-only captures intentionally have no object;
5. active Claim semantic references and typed Evidence requirements resolve;
6. Canon mutation uses prepared/committed snapshots and rollback produces a new
   transaction;
7. runtime deletion followed by rebuild reaches the reported durable watermark
   and can search Canon Claims, readable Evidence, and retained textual
   representations;
8. HTTP authorization, server-side sensitivity limits, Context character
   budgets, and untrusted-content boundaries are enforced;
9. ordinary retention never applies without a fresh preview and exact explicit
   confirmation; an implementation that adds owner erasure MUST provide the
   same preview-bound protection;
10. no required durable data exists only in Docker-managed or runtime state.

The reference software does **not** implement owner-erasure preview/apply, MCP,
vector search, graph traversal or ranking, external collectors, OCR or
transcription pipelines, automatic host preflight/postflight hooks, scheduled
retention apply, or automatic AI extraction and promotion. These features are
outside v0.2 conformance; their presence MUST NOT be implied by a claim that an
installation is v0.2 conformant.

## 21. Resource ceilings and reference scale

The reference implementation applies these input and projection ceilings:

| Area | Limit |
| --- | ---: |
| HTTP request body and CLI raw input | 64 MiB |
| Durable capture/event record | 16 MiB |
| Canon Markdown and indexed text object | 8 MiB |
| Canon YAML frontmatter, CLI mapping, policy, and source metadata | 1 MiB each |
| Installed/vault JSON Schemas | no independent cap; treated as trusted schema input |
| Event `data` member | 4 MiB |
| Context layer defaults (`budget/core/continuity/relevant`) | 24,000 / 8,000 / 4,000 / 12,000 chars |
| Context object and Evidence expansion | 1,000,000 chars |
| Search query / result count | 4,096 chars / 100 |

The YAML loader additionally limits aliases to 50, nesting depth to 64, and
composed/expanded nodes to 100,000. These ceilings bound resource use; they are
not throughput guarantees. Event append and source external-ID lookup scan the
durable record set in O(N), and the reference assumes one durable writer at a
time. The runtime index is disposable and rebuilt from durable files.
