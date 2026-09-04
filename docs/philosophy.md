# LifeDB Philosophy and v0.2 Boundary

Status: v0.2 design baseline

## Purpose

LifeDB is a durable, local-first memory substrate owned by a person. It keeps
accepted knowledge, observations, and retained artifacts usable without a
particular database, model provider, agent host, or container image.

LifeDB does not claim to store truth. It stores what the owner currently accepts,
what a source or process observed, and enough provenance to inspect the
relationship between the two.

## Authority model

LifeDB uses the following terms deliberately:

| Component | Meaning | Authority |
| --- | --- | --- |
| Canon | The owner's accepted current model | Authoritative for current semantic state, but fallible and revisable |
| Canon transactions | Before/after snapshots of accepted changes | Authoritative for Canon history and rollback; no arbitrary as-of query API |
| Evidence | Immutable records of observations, imports, or captures | Authoritative only for what LifeDB recorded; not proof that a source was honest or correct |
| Objects | Retained raw or derived bytes | Authoritative for byte identity while present; availability is policy-dependent |
| Policies | Owner-controlled authorization, retention, and disclosure rules | Authoritative for actions taken by the service |
| Runtime | Search indexes, graphs, embeddings, caches, and effective views | Never authoritative; fully reconstructable |
| Context Packs | Authorized, budgeted runtime selections for a client request | Never authoritative; short-lived and purpose-bound |

Normative documents and user interfaces SHOULD avoid the labels "Semantic
Truth" and "Evidence Truth." Canon is accepted knowledge, and Evidence is an
observation record.

## Governing principles

### Owner sovereignty comes first

The owner, not an agent, model provider, collector, or storage policy, controls
the vault. Normal durable operations are append-only, but append-only history is
not a reason to deny an owner-authorized erasure. An erasure may intentionally
make historical reconstruction incomplete.

"Remember forever" means retain according to an explicit durable policy while
the owner continues to authorize that retention. It does not mean
technically or legally indelible storage.

### Acceptance and observation remain separate

Ingestion creates Evidence, not Canon knowledge. A conversation, web page,
sensor event, or imported profile can be mistaken, malicious, ambiguous, or out
of date. Promotion into Canon is a separate accepted change with its own actor,
reason, inputs, and transaction.

A declaration such as "I use Zed" can be directly supported as a declaration
without proving every possible interpretation of the real-world statement.
Basis, evidential support, acceptance, and current validity MUST NOT be collapsed
into a single numeric confidence value.

### Durable formats outlive implementations

Canon remains readable UTF-8 Markdown with YAML frontmatter. Evidence, lifecycle
events, policies, and transaction manifests use openly specified UTF-8 data
formats. Runtime databases are replaceable projections.

Rebuilds MUST use retained durable representations and MUST NOT require the
original model that produced them. Unknown extension fields must survive any
tool that rewrites a durable record.

### History is explicit

Changing a Canon document is a transaction, whether the change was made by a
human, a deterministic process, or an AI-assisted reconciler. A committed
transaction contains the actor and durable before/after snapshots, not merely a
diff or a pair of hashes. This supports snapshot-based history inspection and
rollback without making Git a required database. The v0.2 reference has no
general arbitrary-time Canon reconstruction API; its implementation exposes
rollback by referring to transaction snapshots.

Rollback creates a compensating transaction. It does not rewrite history. Git
may provide a useful review interface and additional history, but it is not the
only audit or recovery mechanism.

### Payload state is derived, not edited into Evidence

A sealed Evidence capture is never rewritten during normal operation. New
representations, retention changes, holds, missing-object observations,
evictions, and restorations are immutable lifecycle events. Runtime code folds
the capture and its ordered events into an effective view.

Every Claim-to-Evidence edge declares the minimum material it requires:

- `raw`: the captured payload bytes must remain available;
- `representation:<role>`: a retained representation with that role must remain
  available;
- `record-only`: the Evidence record is sufficient and payload bytes may be
  evicted under policy.

Merely citing Evidence does not implicitly pin every raw payload. Conversely, an
unsatisfied `raw` or `representation:<role>` requirement is a visible integrity
failure, not a condition the query layer may silently ignore.

### Disclosure is decided by the server

Clients request context; they do not grant themselves access. The service
in a full deployment derives allowed operations, sensitivity, destination, and
expansion rights from an authenticated client policy. In the v0.2 reference,
one owner Bearer token authorizes all HTTP operations; the server fixes the
principal, destination, and purpose labels and applies one global sensitivity
ceiling/floor and Context-budget profile. There are no per-client operation
scopes or destination/purpose allowlists. A request field such as a sensitivity
ceiling can narrow access but can never widen it.

Context selection applies authorization before retrieval and rendering. It uses
strict total and per-layer budgets, reports truncation and projection freshness,
and marks retrieved material as untrusted data. Neither Canon nor Evidence may
grant tool permissions, disclose secrets, or override host-level instructions.

### Integrity is not authenticity

A cryptographic digest detects a change to known bytes and supports content
addressing. It does not establish who created the bytes, whether capture metadata
is honest, whether a source was authorized, or whether a statement is true.
Authenticity requires a trusted acquisition path, authenticated actor, signature,
or other separately defined evidence.

## Immutability and erasure

Normal operations preserve base records and append new events. Direct mutation
is treated as corruption or an uncommitted manual edit. The following operation
is intentionally different:

1. the authenticated owner selects an exact erasure scope;
2. LifeDB previews affected Claims, Evidence, raw objects, representations,
   transactions, runtime projections, and known backups;
3. the owner authorizes the irreversible boundary;
4. LifeDB removes or cryptographically erases the authorized material and
   rebuilds affected projections;
5. a minimal erasure receipt is retained only when the owner's policy permits
   it.

No automatic policy may invoke owner-authorized erasure. Storage eviction is a
different operation: it follows retention policy, normally leaves the Evidence
record intact, and may be reversible only during a configured trash or backup
window.

## v0.2 core boundary

Version 0.2 is a durable correctness and policy-enforcement kernel. It is not yet
a complete autonomous memory product.

### In scope

- the authority model and threat model;
- immutable Evidence capture records and ordered lifecycle events;
- effective payload and representation views rebuilt from durable files;
- structured Claim evidence requirements (`raw`, `representation:<role>`, and
  `record-only`);
- durable Canon transactions with actor, reason, and before/after snapshots;
- Canon transaction snapshot history and compensating rollback (without a
  general arbitrary-time reconstruction API);
- real schema and cross-record validation, including object reachability and
  digest checks;
- crash-safe atomic writes, a single-writer lock, and deterministic recovery;
- complete lexical indexing of Canon Claims, readable Evidence, and retained
  textual representations;
- projection revision or watermark reporting;
- authenticated local clients, server-side authorization, sensitivity filtering,
  Context Pack budgets, and untrusted-content boundaries;
- manual retention preview/apply/recovery with exact confirmation;
- backup and empty-runtime recovery tests for the durable formats.

The reference has explicit resource ceilings: HTTP/CLI raw input 64 MiB,
durable records 16 MiB, Canon/indexed text 8 MiB, frontmatter/CLI mappings/
policies/source metadata 1 MiB each, event data 4 MiB, Context/Evidence
expansion 1,000,000 characters, queries 4,096 characters, and search results
100. Event append and external-ID lookup are O(N), with one durable writer at a
time. These are safety bounds, not throughput guarantees.

### Out of scope

- automatic AI promotion, Candidate reconciliation, or personality inference;
- automatic storage eviction or autonomous deletion;
- passive screen, audio, mail, calendar, or browser collectors;
- OCR, captioning, transcription, and other extraction pipelines;
- vector search, graph ranking, learned reranking, and model-dependent retrieval;
- automatic preflight/postflight integration for every agent host;
- MCP compatibility and vendor-specific agent adapters;
- multi-writer or multi-device synchronization, federation, and vault merging;
- automatic entity merge/split and a comprehensive predicate ontology;
- application-level object encryption and digital-signature infrastructure.

Deployments still require encrypted storage and encrypted backups appropriate to
their threat environment. Features outside the v0.2 core must not be implied by
conformance claims.

The reference quarantine directory is chiefly retention-transaction staging;
passive collector capture quarantine is future work. Remote exposure also needs
TLS, a reverse proxy, destination policy, rate/quota controls, free-space
monitoring, and security review. The reference has a single owner Bearer token
without operation-level scopes and does not enforce those operational quotas.

Owner-authorized erasure remains a specified safety boundary and design
requirement, but the v0.2 reference implementation does not provide erasure
preview or apply operations. Ordinary retention eviction is the implemented
destructive data operation and preserves sealed Evidence and lifecycle history.
