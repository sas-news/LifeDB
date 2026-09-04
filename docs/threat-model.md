# LifeDB Threat Model

Status: v0.2 design baseline

## Scope and security posture

LifeDB contains a longitudinal record of a person's activities, relationships,
interests, decisions, and inferred traits. Metadata alone may be highly
sensitive. The v0.2 core therefore assumes least disclosure even on a local
machine.

The v0.2 deployment model is one owner, one vault, and one durable writer at a
time. Multiple authenticated readers may use runtime projections. Multi-owner,
multi-writer, federated, and hostile-host operation are outside this threat
model. The reference HTTP service uses one owner Bearer token with no
operation-level scope separation.

The host operating system administrator and the authenticated vault owner are
trusted to authorize administrative operations. Source content, collectors,
agent clients, remote model providers, plugins, and other local processes are
not inherently trusted.

## Assets

LifeDB protects:

- Canon content and its change history;
- Evidence records and source metadata;
- raw objects and derived representations;
- identities, relationships, locations, schedules, habits, and inferences;
- policies, sensitivity labels, holds, and erasure decisions;
- Context queries, Context Packs, session and workspace associations;
- audit actors, lifecycle events, and Canon transactions;
- backup copies and encryption keys managed outside the vault.

Object hashes, perceptual hashes, filenames, sizes, timestamps, and source URIs
are metadata assets. A hash may reveal equality or permit guessing of
low-entropy content even when payload bytes are unavailable.

## Trust boundaries

### Source and collector to Evidence and Objects

Imported files, web pages, messages, transcripts, and collector events are
untrusted input. In the v0.2 reference, capture writes the sealed Evidence
record and (when retained) the Object directly; `quarantine/` is retention-
transaction staging. A future passive collector MAY first stage input in a
capture quarantine before validation. In all cases, input may contain malware,
malformed encodings, secrets, decompression bombs, false metadata, or
instructions intended to manipulate an agent.

### Client to LifeDB service

A client identity, claimed sensitivity ceiling, source label, or actor name in a
request is not trusted merely because the request came from localhost. A full
deployment authenticates the principal and derives authority from server-side
policy. The reference authenticates one owner Bearer token and applies its
server-configured sensitivity and budget limits; request labels do not add
authority.

### Durable stores to runtime projections

Indexes and Context Packs are derived copies. They must preserve authorization
and sensitivity boundaries and must expose their durable revision. A stale or
partial projection must report that condition rather than silently claiming a
complete search.

### LifeDB to a model or agent host

Sending context to a local model, remote model, plugin, or tool is a disclosure.
In a full deployment, destination and purpose are inputs to authorization.
`restricted` material must never leave an approved local execution boundary.
The reference records server-fixed destination and purpose labels but does not
enforce destination/purpose allowlists or remote-egress policy.

### Live vault to backup and restore

Backups cross an administrative and temporal boundary. They need encryption,
integrity verification, retention limits, restoration drills, and an erasure
propagation policy. A live-store deletion alone is not complete erasure.

## Security goals

LifeDB aims to provide:

- confidentiality through authenticated, purpose-bound, server-side access
  control;
- integrity through atomic writes, schema and graph validation, digests, and
  append-only normal history;
- availability through bounded inputs, consistent backups, and empty-runtime
  rebuilds; deployment-level quotas and free-space controls remain required;
- accountability through server-assigned actors and durable transactions;
- owner agency through previews, holds, retention control, and authorized
  erasure;
- safe agent use through explicit untrusted-content boundaries.

LifeDB does not claim that a digest authenticates a source, that a sealed record
is physically impossible to alter, or that an inference becomes true because it
appears in Canon.

## Threats and normative full-deployment controls

The table below states the controls required by the full threat-model design.
The v0.2 reference implements only the subset called out in its reference
qualification text and in the authorization section below.

| Threat | Consequence | Required control |
| --- | --- | --- |
| Unauthenticated local client | Reads or writes personal data | Authenticate every non-health operation; prefer a permission-restricted Unix socket or equivalent local credential |
| Caller raises its own sensitivity ceiling | Unauthorized disclosure | Resolve maximum sensitivity and permitted destinations from server-side client policy; request values may only narrow access |
| Direct Evidence or object lookup bypasses search filtering | Record or metadata disclosure | Apply the same policy to lookup, expansion, search, and context; do not expose objects by digest without an authorized reference |
| Claim-level sensitivity inside a lower-sensitivity document | Whole-document leakage | Enforce the maximum effective label for any returned fragment, or split material into separately authorized documents |
| Malicious prompt text in Evidence or Canon | Tool misuse, exfiltration, or memory poisoning | Render retrieved text in explicit data boundaries; never treat it as host instructions or permission; keep promotion separate from ingestion |
| Compromised collector or spoofed source metadata | False or poisoned observations | Assign producer identity server-side, retain acquisition provenance, support idempotency and replay detection, and treat source assertions as unverified |
| Hash mistaken for authenticity | False confidence in origin | Describe hashes only as byte-integrity and addressing mechanisms; use authenticated acquisition or signatures when authenticity is required |
| Torn or reordered filesystem writes | Sealed partial records or dangling references | Stage, flush, atomically publish, fsync directories, serialize durable writers, and provide deterministic crash recovery |
| Out-of-band Canon edit | History bypass and irreproducible current state | Detect snapshot hash drift; keep valid live edits searchable, and flag the drift for owner review and (when audited history is required) adoption through a Canon transaction |
| Runtime index is stale or incomplete | Relevant memory is silently omitted | Track a durable sequence watermark and indexed schema versions; report degraded or stale status in search and Context Packs |
| Raw payload is evicted despite a Claim dependency | Loss of supporting material | Resolve typed Claim evidence requirements and all holds immediately before deletion under the writer lock |
| Deduplicated object has references with different policies | Premature deletion or label confusion | Compute effective retention and access across all current references; keep labels and holds on references, not in the filename |
| Passive or adversarial ingestion floods storage | Denial of service and backup failure | Enforce request-size in LifeDB; deployment collectors/reverse proxies must add source quota, rate, grace-period, and free-space thresholds before capture (the reference does not enforce per-source quota, rate, or free-space limits) |
| Secret appears in a file, message, or screenshot | Credential compromise | Do not promise perfect detection; apply deployment-specific capture staging/redaction, support owner erasure, and prohibit deliberate credential storage (the reference captures directly to Evidence/Objects and has no passive-collector quarantine) |
| Backup theft or stale backup retention | Long-lived confidentiality loss | Require encrypted backups, separate key custody, retention schedules, inventory, integrity checks, and tested erasure propagation |
| Remote model receives over-broad context | Third-party disclosure | Authorize by destination and purpose, minimize context, prohibit `restricted` egress, and avoid persistent request logging; require TLS and a reviewed reverse proxy for remote exposure |
| Owner requests deletion but derivatives remain | Incomplete erasure | Preview and traverse Evidence, raw objects, representations, Canon snapshots, runtime copies, and known backups before completion |
| Ransomware, disk loss, or bad migration | Loss or corruption of memory | Maintain versioned backups, hash manifests, migration copies, rollback instructions, and restore drills on an independent environment |

## Authorization rules for a full deployment

The following is the normative profile model for a full or multi-client
deployment. Every client has a server-managed profile containing at least:

- principal identity;
- allowed operations;
- maximum sensitivity;
- permitted local or remote destinations;
- whether Evidence expansion is allowed;
- applicable workspace, session, or purpose restrictions;
- request and Context Pack budgets.

The effective authorization is the intersection of client policy, data label,
destination policy, operation, and owner holds. Unknown labels fail closed.
Supplying `client`, `actor`, or `sensitivity_ceiling` in request data does not
authenticate those values.

The v0.2 reference is narrower: it authenticates one owner Bearer token for all
authorized HTTP operations, uses server-fixed principal/destination/purpose
labels, and applies one global server sensitivity and Context-budget profile.
It has no per-client profiles, operation scopes, or destination/purpose
allowlists; request labels are not an authority source.

Object access is mediated through an authorized Evidence or representation
reference. Content-addressed paths are storage details, not bearer capabilities.

## Context and prompt-injection boundary

The Context Builder filters before ranking and renders only authorized items.
Each item identifies its source, sensitivity, truncation, and untrusted status;
Canon items may also carry authorized Evidence handles. Freshness and durable
revision are reported at pack level by the global watermark, not on each item.
Retrieved text is delimited and described as potentially adversarial.

Canon Core may contain accepted preferences and constraints, but it cannot grant
filesystem, network, tool, model, or secret access. Host system policy remains
above every LifeDB layer. Evidence content never becomes Core merely because it
contains instruction-like language.

Context Packs are short-lived runtime artifacts. Implementations should avoid
persisting full queries and rendered packs; any operational logging must be
minimal, access-controlled, and covered by retention and erasure policy.

## Owner-authorized erasure

Erasure is a privileged, destructive exception to normal append-only operation.
It requires strong owner authentication, exact resolved targets, an impact
preview, and explicit confirmation. Authorization for retention management does
not automatically authorize erasure.

An erasure traversal includes semantic references, capture records, lifecycle
events, raw objects, derived representations, Canon transaction snapshots,
runtime projections, trash windows, and known backup generations. LifeDB must
state which external or offline copies it cannot control. If the owner requests
total removal, an audit tombstone must not preserve the removed personal data.

## Residual risks and non-goals

The v0.2 core does not defend against a malicious host administrator with access
to plaintext memory, an already compromised owner account, hardware key theft,
traffic analysis outside the host, or copies exported beyond LifeDB's control.
Application-level encryption, signatures, multi-party authorization, remote
attestation, and multi-user isolation are future work.

Operational deployment therefore requires a maintained host, encrypted storage,
encrypted off-site backups, restricted filesystem permissions, key separation,
and periodic restore and access reviews.
