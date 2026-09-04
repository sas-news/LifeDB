# ADR 0001: Durable files and disposable runtime

Status: accepted

## Decision

LifeDB stores Canon as Markdown with YAML frontmatter, Evidence as immutable
JSON, and payloads as SHA-256-addressed files. Every database and search index is
a disposable projection.

Docker bind-mounts the host vault. Docker named or anonymous volumes may be used
for caches, but never as the only location of durable knowledge.

## Consequences

- A simple editor can inspect Canon.
- Evidence can be parsed without the original application.
- Database-specific features may be added without changing ownership.
- Rebuild time is accepted as the cost of portability.
- Schema validation and recovery testing become release requirements.
- High-volume Evidence must be partitioned or batched to avoid excessive files.
