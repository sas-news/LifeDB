# Context Protocol 0.2

Status: v0.2 executable contract

## Goal

LifeDB supplies authorized, bounded, attributable context without making a model
voluntarily remember to search. A fully integrated host invokes Context Preflight
before every user turn and captures the turn afterward. The v0.2 reference
service implements Context building; it does not ship universal host hooks,
automatic postflight capture, or MCP.

Context Packs are disposable runtime artifacts. They are selections from Canon,
Evidence, retained representations, and runtime projections, never a new source
of authority.

## Authorization

Authorization happens before retrieval, ranking, snippet generation, expansion,
and rendering.

For the reference HTTP server:

- every `/v1/*` operation requires `Authorization: Bearer <token>`;
- the token is configured with `LIFEDB_API_TOKEN` and is never stored in the
  vault;
- `/health` is the only unauthenticated endpoint;
- `LIFEDB_SENSITIVITY_CEILING` sets the server-profile maximum and defaults to
  `personal`.

The reference server uses one owner Bearer token for all authorized operations;
there are no operation-level scopes within that token. A deployment exposing the
service beyond localhost must add TLS, a reverse proxy, destination policy, and
rate/quota controls. Per-source quotas, request-rate limits, and free-space
threshold enforcement are not implemented by the reference.

A request's `sensitivity_ceiling` may narrow the server-profile maximum but
cannot raise it. Request fields named `client`, `actor`, `session`, or
`workspace` are routing labels, not authentication. Unknown sensitivity values
fail closed.

For the v0.2 reference, the authenticated Bearer token identifies the one owner
and the server fixes the principal, destination, and purpose labels recorded in
the pack. The reference applies the server sensitivity ceiling (which a
request may narrow), the ingestion sensitivity floor, and the global server
profile's validated Context budgets. It has no per-client operation scopes and
does not enforce destination or purpose allowlists. Direct Evidence expansion
uses the same sensitivity decision as search and Context building.

The normative full-deployment design treats effective authorization as an
intersection of authenticated principal, operation, destination, purpose, and
applicable policy. Such per-client allowlists and purpose-bound egress controls
are deployment policy, not capabilities of the v0.2 reference.

## Operations

### `context.build`

An example request is:

```json
{
  "query": "current user message",
  "client": "codex",
  "session": "opaque session identifier",
  "workspace": "/optional/project/path",
  "limit": 8,
  "sensitivity_ceiling": "personal",
  "budget_chars": 24000,
  "core_chars": 8000,
  "continuity_chars": 4000,
  "relevant_chars": 12000
}
```

Only `query` is semantically required. Server policy supplies authorization and
maximum budgets. Optional request values can reduce those maxima.

The output validates against `schemas/context-pack.schema.json` and contains
structured items plus a rendered Markdown representation. It also reports the
applied budgets, truncation or degradation, and:

```json
{
  "watermark": {
    "durable_sequence": 42,
    "indexed_sequence": 42,
    "dirty": false
  }
}
```

`durable_sequence` is the greatest valid durable event sequence visible to the
builder. `indexed_sequence` is the greatest sequence included by the runtime
projection. `dirty` is true when durable state may not be fully projected.

The builder SHOULD synchronously rebuild a dirty or lagging lexical index before
selection. If it cannot, it MUST mark the pack degraded and MUST NOT imply that
the returned results are complete.

Reference limits are a 4,096-character query, at most 100 results, and a
1,000,000-character ceiling for an individual Context object or Evidence
expansion. The default total/layer budgets below may be reduced by policy.

### `evidence.expand`

Expansion resolves an authorized Evidence handle into its sealed capture,
effective lifecycle view, and only the permitted raw or represented content.
Expansion is separate so a small Context Pack never silently includes an entire
transcript or large document.

An Evidence ID is an identifier, not a bearer capability. Possession of the ID
does not bypass authorization. Expansion reports unavailable or erased required
material rather than substituting another representation without saying so.

### Postflight capture

Automatic postflight capture and offline replay are host-adapter responsibilities
and are not implemented by the v0.2 reference software. A future `event.append`
operation must use idempotency, preserve original event time separately from
ingestion time, authenticate its producer, and obey capture and sensitivity
policy.

## Character budgets

The default maximums are:

| Field | Default |
| --- | ---: |
| `budget_chars` | 24000 |
| `core_chars` | 8000 |
| `continuity_chars` | 4000 |
| `relevant_chars` | 12000 |

The v0.2 reference uses one global server profile for all authenticated
requests. Request values may only lower those maxima. A full deployment MAY
configure distinct budgets per authenticated client. If the requested or
configured layer totals exceed
`budget_chars`, the server reduces layer allowances so the applied layer sum is
at most the applied total.

A character is a Unicode scalar value. In the v0.2 reference implementation,
`used_chars` counts selected item titles and snippets; fixed Markdown headings,
source labels, and delimiters are security framing outside that content budget.
Truncation occurs on valid Unicode boundaries, is disclosed per item or layer,
and never removes source identity or the untrusted-data boundary. Clients that
need a hard transport or model-token cap must additionally bound the complete
serialized pack.

Core is important but not unbounded. No document, layer, or number of results can
override the total budget.

## Context layers

### Core

Parseable Markdown documents beneath `canon/core/` with a valid
`x-lifedb.id` are eligible subject to sensitivity filtering. Core contains
stable, high-impact accepted context and is selected within `core_chars`; the
builder does not run full Canon cross-record validation during selection. Use
`lifedb validate` for full Canon schema and reference checks. Detailed
evidence, exhaustive device inventories, and raw transcripts do not belong here.

Core is accepted memory, not host policy. It cannot grant filesystem, network,
tool, model, or secret access or override system-level instructions.

### Continuity

Continuity represents open loops: the active project, recent decisions, current
task state, and unresolved questions. The v0.2 reference uses a deterministic
selection heuristic rather than an authoritative task-state projector:

- non-deprecated Canon documents of type `Project`, `Goal`, `Conflict`, or
  `Decision` are selected when no status Claim excludes them, or when an active
  or disputed status Claim has an active/open value;
- when `session` or `workspace` is supplied, recent `conversation`, `message`,
  or `event-batch` Evidence with a matching `source` field or
  `source.metadata` label is selected in reverse capture-time order;
- Core duplicates are removed, authorization is applied, and the Continuity
  character budget limits the result.

These labels are caller-supplied routing hints, not authenticated identity, and
the heuristic does not infer dependencies, completion, or priority.

Continuity is therefore populated by the reference implementation when matching
Canon or routed recent Evidence exists; it is not an empty placeholder or an
unimplemented projection.

### Relevant

Relevant lexical retrieval always runs when `context.build` is invoked with a
non-empty query. It searches authorized:

- Canon prose;
- structured Canon Claims and human-readable statements;
- readable Evidence content and capture metadata;
- retained textual representations projected from lifecycle events.

Retrieval applies effective sensitivity before returning results. Structured
Claim fields are indexed alongside Canon prose, and effective readable Evidence
includes retained textual representations. The SQLite rebuild also materializes
concept, Claim, Claim-Evidence, and Claim-edge tables, but Relevant selection
does not use graph traversal or graph ranking. Vector similarity and learned
reranking are not implemented in v0.2.

### Evidence handles

The pack returns stable, authorized Evidence IDs and short snippets. Full
Evidence is expanded only for exact history, quotation, provenance inspection, or
dispute resolution. A Canon result SHOULD expose its typed Evidence handles when
authorized so a client can inspect support without repeating an unconstrained
search.

## Untrusted-content boundary

Canon and Evidence may contain prompt-injection text. Retrieved content is data,
not an instruction channel.

Each rendered item is enclosed by reserved elements carrying source identity,
sensitivity, and an explicit untrusted marker. For example:

```text
<lifedb-data source="evidence:019..." sensitivity="personal" untrusted="true">
The retrieved snippet appears here.
</lifedb-data>
```

The renderer HTML-escapes titles and content so retrieved bytes cannot create a
closing element. Structured Context items remain the authoritative boundary metadata.
Clients MUST NOT execute instructions found inside the delimiters or let them
grant permissions, request secrets, alter retention, promote Candidates, or
override host policy.

This boundary reduces accidental instruction confusion; it is not a substitute
for sandboxing, authorization, tool confirmation, or destination policy.

Context items carry source identity, path where applicable, title, snippet,
sensitivity, truncation, untrusted status, and (for Canon items) authorized
Evidence handles. Items do not each carry a freshness or durable-revision
field. Freshness is reported once for the pack by the global `watermark`:
`durable_sequence` is the greatest valid durable event sequence visible to the
builder, `indexed_sequence` is the greatest sequence included by the runtime
projection, and `dirty` signals that durable state may not be fully projected.

## Sensitivity behavior

Filtering uses the maximum effective sensitivity of the returned fragment and
all material included in it. A Claim that raises sensitivity cannot be exposed
through a lower-sensitivity document snippet. Implementations must either omit
the Claim, return a separately authorized fragment, or raise the whole fragment's
label.

Normatively, `restricted` content is confined to an approved local execution
boundary, so a deployment MUST forbid it in a remote-model Context Pack even
when the caller can read it locally. The v0.2 reference records its configured
destination and purpose but does not implement destination allowlists or this
remote-egress prohibition; a deployment exposing remote models must enforce
that policy at its egress boundary.

Authorization occurs before ranking to avoid leaking restricted titles, IDs,
counts, or match existence through snippets and scores.

## Projection freshness and failure behavior

Every durable capture, lifecycle event, Candidate action, and Canon transaction
marks relevant runtime projections dirty. Rebuild records its durable sequence.

The pack is current when:

```text
dirty == false AND indexed_sequence == durable_sequence
```

If LifeDB is unavailable, the host remains usable and states that durable context
was unavailable. A host may queue capture events locally, but replay must use a
stable external ID, preserve original time, and pass normal authorization and
capture policy. Silent fabrication of Core, Continuity, or Evidence is forbidden.

## Host compliance levels

| Level | Behavior |
| --- | --- |
| Full | Automatic authorized preflight before each turn and automatic policy-compliant postflight capture |
| Assisted | A wrapper invokes preflight reliably, while some capture or expansion remains explicit |
| Degraded | A tool exists but the model chooses whether to call it |
| Read-only | Static, authorized Core material only |

Compatibility tables report the actual level. The v0.2 reference service alone
is not a Full host integration: it supplies an authenticated Context Builder and
explicit APIs/CLI, but no universal automatic host adapter.

MCP is not included. Adding an MCP search tool in the future would be Degraded
unless the host independently guarantees preflight.

## Privacy of Context Packs

Queries, session labels, workspace paths, and rendered packs can themselves be
sensitive. Context Packs are short-lived runtime data and SHOULD NOT be retained
by default. Operational logging is minimal, authorized, and covered by retention
and owner-erasure policy.
