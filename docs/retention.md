# Retention Policy 0.2

Status: v0.2 executable contract

## Retention promise

LifeDB retains observations and payloads according to owner-controlled policy; it
does not promise indelible storage. During normal operation, capture records and
lifecycle events are append-only. The owner may explicitly authorize erasure,
even when that makes history, as-of reconstruction, or rollback incomplete.

For retained Evidence, LifeDB can report:

1. what was observed or ingested;
2. when and from where it came;
3. what raw and derived objects were recorded;
4. which current Claims require raw, represented, or record-only support;
5. whether each required object is currently available;
6. which policy, actor, and event changed payload state.

This does not require every passive capture or reproducible public asset to be
stored forever.

## Retention classes

| Class | Meaning |
| --- | --- |
| `pinned` | Excluded from ordinary eviction previews until an explicit owner or hold change |
| `durable` | Retained until an explicit, reviewed retention change |
| `grace` | Eligible for preview only after its declared grace condition |
| `derivative-only` | Raw bytes may be proposed only after all required durable representations exist |
| `reference-only` | URI and metadata are retained; the original payload object was never stored |

`reference-only` requires an absolute source URI. Ingestion records content
size and digest but does not write the supplied original bytes to
`objects/sha256/`; initial payload state is `external` and `payload.object` is
absent.

Suggested defaults are:

| Input | Default |
| --- | --- |
| Explicit manual ingest | `durable` |
| User-created or irreplaceable media | `pinned` |
| Structured text explicitly captured by the owner | `durable` |
| Reproducible public asset captured only for provenance | `reference-only` or `derivative-only` after review |
| Generated intermediate with no durable dependency | Runtime or `reference-only` |

Passive screenshots, continuous audio, external collectors, and automatic
classification are outside v0.2. A future collector must declare its own quotas,
grace periods, idempotency behavior, and default sensitivity before deployment.

## Claim requirements

Retention follows the typed edge from a current accepted Claim to Evidence:

- `requires: raw` requires the capture payload object to remain present;
- `requires: representation:<role>` requires at least one verifying durable
  representation with that exact role;
- `requires: record-only` requires only the sealed capture record.

A citation is not automatically a raw-byte pin. Conversely, storage pressure
cannot weaken an explicit requirement. A legacy bare Evidence UUID is treated as
`requires: raw` until migrated.

Historical Claim text in a Canon transaction snapshot is not by itself a live
raw-byte pin. Canon before/after snapshot objects are nevertheless protected
because they are required for audit and rollback. An archival or legal hold may
also retain historical Evidence payloads.

## Effective retention for deduplicated objects

An object digest may be referenced by multiple captures, representations,
Claims, or transactions with different sensitivities and retention policies.
LifeDB computes effective retention across all current references before
proposing that digest.

The effective decision is the strongest of:

- typed requirements from current accepted or disputed Claims;
- prepared and committed Canon snapshot dependencies;
- explicit owner, archival, or legal holds;
- each referencing capture's retention class;
- durable representation dependencies;
- policy-specific minimum dates or conditions.

Deleting one reference never authorizes deletion of shared bytes. Sensitivity
and authorization also remain attached to references; an object's pathname or
digest is not a read capability.

## Representations

Representations include extracted text, OCR, speech transcripts, captions,
thumbnails, perceptual hashes, metadata, and normalized structured records.
They are added with immutable `representation.added` lifecycle events and record:

- a non-empty role;
- object digest and media type;
- producer and version;
- creation time;
- source object or Evidence derivation.

The v0.2 core can record and project representations but does not generate OCR,
captions, or transcripts.

Before proposing raw-byte eviction for `derivative-only`, the service verifies
that every required role has at least one present, digest-valid durable object.
After raw eviction, a retained representation is durable Evidence and not a
recomputable runtime cache.

## Two-phase retention operation (implemented manually)

Version 0.2 performs no scheduled or automatic deletion. Every ordinary
retention change is an explicit two-phase operation.

The reference CLI implements all three manual operations: `preview` writes and
returns a persisted plan, `apply` performs exact-confirmation eviction after
revalidation, and `recover` repairs interrupted apply transactions. None of
these commands runs in the background.

### Preview

A preview does not change durable state or remove objects. The reference CLI
persists it beneath `runtime/retention/` and returns:

- a unique preview ID and exact `confirmation` digest;
- generation time and durable event sequence;
- the SHA-256 digest of the applied policy file;
- exact object digests and estimated bytes;
- affected Capture IDs for each candidate;
- blocked objects with dependency, hold, retention-class, grace-period,
  representation, snapshot, or missing-object reasons.

The preview excludes any object whose current dependencies are not satisfied. A
preview is not deletion authority.

### Explicit apply

Apply requires the exact preview ID and integrity value plus explicit
confirmation of the resolved target set. Under the single-writer lock, LifeDB
recomputes dependencies, holds, object digests, and the durable sequence.

If anything differs, the preview is stale and apply fails closed. The caller must
request and review a new preview. A general approval such as "apply current
policy" is insufficient.

For each successful payload eviction, LifeDB:

1. verifies that all typed requirements and holds remain satisfied;
2. removes or moves only the exact approved object bytes;
3. appends an immutable `payload.evicted` event with actor, reason, policy
   version, preview reference, and resulting state;
4. marks runtime projections dirty;
5. returns an apply report including bytes affected and any failures.

A partial apply is never reported as complete. Recovery folds only durable events
whose corresponding filesystem action was completed or deterministically
reconciled.

The reference implementation appends `retention.apply-prepared`, moves exact
candidate objects beneath transaction-scoped `quarantine/retention/`, appends
`payload.evicted` and `retention.apply-committed`, then removes quarantined
bytes. `lifedb retention recover` restores objects and appends compensating
events for prepared-only transactions, or cleans quarantine residue for a
committed transaction. It does not schedule either preview or apply.

Because quarantine contains the only staged copy while an apply is prepared or
in flight, it MUST be included in a consistent backup of that transaction. In
the current v0.2 implementation quarantine is for retention transactions, not a
passive-collector landing area.

The exact CLI sequence is:

```sh
lifedb retention preview
lifedb retention apply <plan-id> --confirm 'sha256:<confirmation>' \
  --actor owner:local
lifedb retention recover
```

`<plan-id>` and `<confirmation>` must be copied from the preview output. An
empty candidate list is valid and causes no payload eviction.

## Eviction preconditions

An object may appear in an ordinary eviction preview only when all are true:

1. every referencing retention class permits a proposal;
2. no current Claim has an unsatisfied `raw` requirement for it;
3. every required `representation:<role>` remains present and verifies;
4. no prepared or committed Canon transaction snapshot needs it;
5. no legal, archival, or owner hold applies;
6. the policy version and grace conditions are satisfied;
7. the resulting effective Evidence view remains valid;
8. the proposal reports recoverability and exact estimated bytes.

`pinned` and irreplaceable objects are never offered for ordinary apply. Changing
or removing the policy that pins them is a separate explicit action.

## Payload lifecycle

The sealed capture records state at capture and is never edited by retention.
Current state is projected from immutable events in global sequence order.

Relevant event types include:

- `retention.changed`;
- `hold.placed` and `hold.released`;
- `payload.eviction-proposed`;
- `payload.evicted`;
- `payload.missing-observed`;
- `payload.restored`;
- `payload.redacted`.

Restoration succeeds only when restored bytes match the original content digest.
A digest match confirms byte equality, not source authenticity.

## Owner-authorized erasure

Erasure is distinct from ordinary payload eviction. It may remove capture
records, lifecycle events, objects, representations, Canon content or snapshots,
and runtime projections instead of leaving an observation envelope.

Erasure requires:

1. strong owner authorization;
2. an exact scope expressed by resolved IDs and digests, never an unresolved glob;
3. a preview of affected current Claims, transaction history, rollback ability,
   derived content, runtime copies, and known backups;
4. confirmation that identifies that exact preview and target set;
5. a final report of completed, failed, and externally outstanding actions.

No automatic policy, model, Candidate reconciler, collector, or storage-pressure
job may exercise owner-erasure authority.

This section specifies a future safety boundary. The v0.2 reference software
does not implement owner-erasure preview or apply. Ordinary retention is not an
erasure substitute because it preserves Capture and lifecycle Event records.

A minimal erasure receipt is retained only when allowed by the requested scope.
If total removal forbids a receipt, LifeDB must not retain the removed personal
data merely for audit convenience.

## Backups and external responsibility

An apply or erasure operation controls the live vault and its runtime projections.
LifeDB can inventory configured backups and report their impact, but it cannot
guarantee deletion from offline disks, snapshots, remote backup providers,
exports, or copies held by agent/model providers.

The deployment operator is responsible for:

- encrypted backup storage and separate key custody;
- a known backup inventory and expiry schedule;
- deleting or expiring backup generations affected by owner erasure;
- preventing an old restore from silently reintroducing erased material;
- documenting any external copy that cannot be removed.

An ordinary payload eviction does not retroactively delete backup copies unless
backup policy says so. Owner erasure must address them explicitly.

## Storage pressure

Storage pressure produces reports and previews, never autonomous apply. Policies
may group candidates by source, age, reproducibility, role, sensitivity, and
estimated freed bytes. Quotas and free-space thresholds may reject or pause new
capture, but they do not grant deletion authority.

The reference implementation does not enforce per-source quotas, request-rate
limits, or free-space thresholds. Deployments that ingest untrusted or remote
sources must enforce these controls at the collector, reverse proxy, or host
boundary.
