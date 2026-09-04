# Disaster Recovery 0.2

## Recovery objective

LifeDB must remain understandable and recoverable on an empty machine with:

- the repository or a copy of the matching specification, schemas, and
  migrations;
- a consistent copy of the durable vault;
- a Python interpreter, the matching container image, or an independent
  implementation of the documented formats.

Docker is a normal deployment path, not the only decoding path. Recovery does
not require access to an AI model or the model that created a retained
representation.

## Required backup set

Back up:

1. `vault.json`;
2. the complete `canon/` tree;
3. Evidence captures and the complete `evidence/_events/` sequence;
4. all retained `objects/`, including Canon before/after snapshot objects;
5. `policies/`, `schemas/`, and `migrations/`;
6. `quarantine/` whenever a retention transaction is prepared or in flight;
7. a backup manifest containing the included durable event sequence, file list,
   sizes, and externally protected integrity hashes.

`runtime/`, indexes, caches, container layers, downloaded model weights,
Context Packs, and embeddings are not required for semantic recovery.

A valid `reference-only` capture intentionally has no payload object. It remains
recoverable as an observation record and URI, not as original bytes.

## Consistent backup boundary

A file-by-file copy taken across concurrent durable writes may combine a Canon
tree, Event sequence, and Object Store from different transaction states.
Backups therefore use one of:

- a filesystem or storage snapshot taken after quiescing the single writer; or
- a LifeDB backup operation that captures a declared durable sequence and all
  objects and Canon snapshots reachable at that sequence.

The manifest records the greatest included durable event sequence and the
current Canon transaction state. Prepared but uncommitted Canon transactions and
their snapshots are included so recovery can complete or compensate them.

LifeDB record and object digests detect changes to known bytes. They do not
authenticate who made the backup. Backup manifests SHOULD be signed or otherwise
protected by the backup system outside the vault.

## Recovery procedure

1. Restore the repository or matching v0.2 specification, schemas, and
   migrations.
2. Restore the durable backup into a new, empty target directory.
3. Verify the external backup manifest before executing vault content.
4. Validate `vault.json`, every Canon document, capture, lifecycle event,
   Candidate event, and Canon transaction event.
5. Verify each record `integrity`, global `sequence`, and `previous_event`
   linkage through the manifest's durable sequence.
6. Verify every present raw, representation, and Canon snapshot object against
   its SHA-256 path. Do not flag an intentional reference-only absence.
7. Resolve prepared Canon transactions:
   - if a matching committed event exists, ensure current Canon equals its after
     snapshot;
   - if no commit exists, deterministically restore the before snapshot or finish
     the documented commit protocol;
   - record the recovery decision as a new event when the recovered writer is
     available.
8. Verify current Canon against the latest committed transaction and validate
   semantic IDs, Claim references, typed Evidence requirements, supersession,
   sensitivity, and temporal fields.
9. Fold each capture and its lifecycle events to reconstruct effective payload
   state and representations.
10. Delete or omit all `runtime/` state and run `lifedb rebuild`.
11. Confirm the runtime watermark reaches the restored durable sequence and is
    not dirty.
12. Run known lexical searches over Canon Claims, readable Evidence, and a
    retained textual representation.
13. Build an authenticated Context Pack and verify Core, character budgets,
    untrusted-content delimiters, sensitivity filtering, and watermark.
14. Inspect pending manual Candidates without promoting them.
15. Record the drill date, backup generation, durable sequence, software
    version, duration, recovery actions, and failures.

Recovery should be tested periodically, after every durable-format migration,
and after changes to backup, retention, authentication, or encryption policy.

## Runtime deletion drill

Stop the server first. Use the guarded runtime command against the exact
initialized vault; it refuses broad, symlinked, or uninitialized targets:

```sh
docker compose down
docker compose run --rm lifedb runtime reset --confirm DELETE-RUNTIME
docker compose run --rm lifedb rebuild
docker compose run --rm lifedb validate
```

The command only targets `runtime/`; the operator must use the exact configured
vault path and must not substitute a broad path, home directory, or unresolved
environment variable. This is an explicit destructive operation against
disposable state, not a general filesystem deletion recipe.

After rebuild, `indexed_sequence` equals `durable_sequence`, `dirty` is false,
and search and Context authorization produce the expected results.

## Canon rollback drill

At least one recovery drill per release exercises a non-sensitive fixture:

1. create a manual Candidate;
2. promote it through `canon.change-prepared` and
   `canon.change-committed`;
3. verify both snapshot objects;
4. invoke rollback;
5. verify `canon.rollback-prepared` and `canon.rollback-committed`;
6. verify Canon bytes match the original before snapshot;
7. verify both the original and compensating transaction remain auditable.

An interrupted prepared transaction fixture is also required so recovery does not
depend only on the successful path.

## Retention and erasure recovery

Ordinary retention apply records payload lifecycle events. After restore, the
effective view must agree with the restored object set. A missing object whose
effective state is `present` is corruption; an absent object whose effective
state is `evicted`, `redacted`, or validly `external` is not automatically
corruption.

Before validation after an unclean shutdown, run `lifedb retention recover`.
It restores exact quarantined objects and appends compensating restoration and
abort events for prepared-only retention transactions; for committed
transactions it removes leftover quarantine bytes. It does not infer or apply a
new retention plan.

The v0.2 reference implements retention `preview`, exact-confirmation `apply`,
and interrupted-apply `recover` as explicit CLI operations. Recovery does not
make retention automatic or scheduled; it only reconciles an already-started
manual apply.

Owner-authorized erasure may intentionally remove records, snapshot bytes, or
history needed for an as-of view. The recovery report must distinguish an
authorized erasure boundary from unexplained loss whenever a permitted erasure
receipt or backup policy provides that information.

Owner-erasure execution is not implemented by the v0.2 reference software; this
paragraph defines recovery requirements for a future conforming implementation.

LifeDB cannot erase offline or provider-managed backup copies by itself. The
deployment operator owns backup inventory, deletion and expiry, and preventing a
restore from reintroducing erased material. If an old generation must be
retained, that limitation is disclosed to the owner during erasure preview.

## Git is not a complete backup

Git is useful for reviewing Canon prose, but Canon transaction events and exact
before/after snapshot objects are the LifeDB rollback contract. A Git repository
does not include high-volume Evidence or Objects by default and may have
rewriteable history.

A repository mirror is not a complete LifeDB backup unless it includes the full
required backup set and a consistent durable-sequence manifest.

## Release gate

A v0.2 release is not recoverability-verified until:

- all unit and integration tests pass;
- a Docker-capable host completes the runtime deletion drill;
- a fresh target completes the full restore procedure;
- a Canon rollback and interrupted-preparation fixture recover correctly;
- reference-only absence and retained-representation search are tested;
- authentication and sensitivity checks still hold after rebuild.
