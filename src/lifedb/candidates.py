from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from .canon import (
    SENSITIVITIES,
    SENSITIVITY_RANK,
    CanonStore,
    CanonTransactionError,
    validate_claim_proposal,
)
from .ids import is_uuid7, new_id
from .storage import DurablePublicationUncertain, file_lock
from .evidence import iter_events


TERMINAL_EVENT_TYPES = {"candidate.promoted", "candidate.rejected"}
REOPEN_EVENT_TYPE = "candidate.reopened"
CANDIDATE_EVENT_TYPES = {"candidate.created", *TERMINAL_EVENT_TYPES, REOPEN_EVENT_TYPE}


class CandidateError(RuntimeError):
    """Base class for Candidate projection and transition failures."""


class CandidateNotFoundError(CandidateError):
    """No Candidate creation event exists for the requested UUID."""


class CandidateIntegrityError(CandidateError):
    """Candidate events do not form a valid append-only projection."""


class CandidateStateError(CandidateError):
    """The requested transition is invalid for the projected state."""


class CandidateStore:
    """Append-only Candidate commands and deterministic event projections."""

    def __init__(self, vault: Any):
        self.vault = vault
        self.root = Path(vault.root).resolve()
        self.canon = CanonStore(vault)

    def create(
        self,
        target_document_id: str,
        claim: Mapping[str, Any],
        *,
        actor: str,
        sensitivity: str = "personal",
    ) -> dict[str, Any]:
        if not is_uuid7(target_document_id):
            raise ValueError("target_document_id must be a UUIDv7")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        if sensitivity not in SENSITIVITIES:
            raise ValueError("sensitivity is invalid")
        # Candidate creation snapshots target Canon and its sensitivity under
        # the same global writer lock used by Canon mutations. This prevents a
        # document sensitivity change from racing a low-labelled Candidate.
        with file_lock(self.root / "runtime" / "locks" / "writer.lock"):
            proposal = self.canon.validate_proposal(target_document_id, claim)
            target = self.canon.find_document(target_document_id)
            extension = target.frontmatter.get("x-lifedb", {})
            document_sensitivity = extension.get("sensitivity", "personal")
            if document_sensitivity not in SENSITIVITIES:
                raise CandidateIntegrityError("target Canon document has invalid sensitivity")
            event_sensitivity = max(
                (sensitivity, document_sensitivity, proposal.get("sensitivity", document_sensitivity)),
                key=lambda value: SENSITIVITY_RANK[value],
            )
            candidate_id = new_id()
            data = {
                "candidate_id": candidate_id,
                "target_document_id": target_document_id,
                "claim": proposal,
            }
            event = self.vault.append_event(
                "candidate.created",
                actor=actor,
                data=data,
                target=candidate_id,
                sensitivity=event_sensitivity,
            )
        return self._project(candidate_id, [event])

    def get(self, candidate_id: str) -> dict[str, Any]:
        if not is_uuid7(candidate_id):
            raise ValueError("candidate ID must be a UUIDv7")
        return self._project(candidate_id, self._events_for(candidate_id))

    def list(self, *, status: str | None = None) -> list[dict[str, Any]]:
        if status is not None and status not in {"pending", "promoted", "rejected"}:
            raise ValueError("candidate status is invalid")
        candidate_ids = {
            event.get("target")
            for event in self._all_events()
            if event.get("event_type") == "candidate.created" and is_uuid7(event.get("target"))
        }
        candidates = [self.get(candidate_id) for candidate_id in candidate_ids]
        candidates.sort(key=lambda candidate: (candidate["created_at"], candidate["id"]))
        if status is not None:
            candidates = [candidate for candidate in candidates if candidate["status"] == status]
        return candidates

    def reject(self, candidate_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("rejection reason must be a non-empty string")
        with self._candidate_lock(candidate_id):
            candidate = self.get(candidate_id)
            self._require_pending(candidate)
            self.vault.append_event(
                "candidate.rejected",
                actor=actor,
                data={"candidate_id": candidate_id, "reason": reason},
                target=candidate_id,
                sensitivity=candidate["sensitivity"],
            )
            return self.get(candidate_id)

    def promote(self, candidate_id: str, *, actor: str) -> dict[str, Any]:
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        with self._candidate_lock(candidate_id):
            candidate = self.get(candidate_id)
            self._require_pending(candidate)
            # A process can die after Canon is committed and before the
            # candidate terminal event. Reuse that durable promotion instead
            # of appending a second Claim transaction. A committed rollback
            # explicitly re-opens the candidate for a fresh promotion.
            existing = self.canon._committed_promotions_for_candidate(candidate_id)
            if len(existing) > 1:
                raise CanonTransactionError(
                    "Candidate has multiple committed Canon promotions; refusing to choose one"
                )
            if existing:
                transaction = existing[0]
                self.vault.append_event(
                    "candidate.promoted",
                    actor=actor,
                    data={
                        "candidate_id": candidate_id,
                        "transaction_id": transaction["transaction_id"],
                        "claim_id": transaction["claim"],
                    },
                    target=candidate_id,
                    sensitivity=candidate["sensitivity"],
                )
                return self.get(candidate_id)
            transaction = self.canon.promote(candidate, actor=actor)
            try:
                self.vault.append_event(
                    "candidate.promoted",
                    actor=actor,
                    data={
                        "candidate_id": candidate_id,
                        "transaction_id": transaction["transaction_id"],
                        "claim_id": transaction["claim"],
                    },
                    target=candidate_id,
                    sensitivity=candidate["sensitivity"],
                )
            except Exception as exc:
                # The terminal Event name may already be durable when its
                # directory fsync is uncertain.  Canon recovery can reconcile
                # the committed promotion; a rollback here would make the
                # append-only history contradictory.
                if isinstance(exc, DurablePublicationUncertain):
                    raise CanonTransactionError(
                        "Candidate promotion Event publication is uncertain; recovery is required"
                    ) from exc
                try:
                    self.canon.rollback(transaction["transaction_id"], actor=actor)
                except Exception as rollback_exc:
                    raise CanonTransactionError(
                        "Candidate promotion event failed and Canon compensation failed: "
                        f"{rollback_exc}"
                    ) from exc
                raise CanonTransactionError(
                    "Candidate promotion event failed; Canon promotion was rolled back"
                ) from exc
            return self.get(candidate_id)

    def rollback(self, transaction_id: str, *, actor: str) -> dict[str, Any]:
        if not is_uuid7(transaction_id):
            raise ValueError("transaction ID must be a UUIDv7")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        source = self.canon._committed_transaction(transaction_id)
        candidate_id = source.get("candidate")
        claim_id = source.get("claim")
        if not is_uuid7(candidate_id) or not is_uuid7(claim_id):
            raise CanonTransactionError("Canon promotion has an invalid Candidate identity")
        with self._candidate_lock(candidate_id):
            rollback = self.canon.rollback(transaction_id, actor=actor)
            # The rollback is an append-only Canon transaction.  Reopen the
            # Candidate under the same lock so a concurrent promote cannot
            # observe a rollback without its projection transition.
            existing = [
                event for event in self._events_for(candidate_id)
                if event.get("event_type") == REOPEN_EVENT_TYPE
                and isinstance(event.get("data"), Mapping)
                and event["data"].get("rollback_id") == rollback["transaction_id"]
            ]
            if not existing:
                candidate = self.get(candidate_id)
                try:
                    self.vault.append_event(
                        REOPEN_EVENT_TYPE,
                        actor=actor,
                        data={
                            "candidate_id": candidate_id,
                            "transaction_id": transaction_id,
                            "claim_id": claim_id,
                            "rollback_id": rollback["transaction_id"],
                        },
                        target=candidate_id,
                        sensitivity=candidate["sensitivity"],
                    )
                except Exception as exc:
                    # Canon rollback is already durable.  Leave the missing
                    # projection transition for Canon recovery; never attempt
                    # a second Canon mutation or claim a rollback failure.
                    raise CanonTransactionError(
                        "Candidate reopen Event publication failed; recovery is required"
                    ) from exc
            return rollback

    @staticmethod
    def _require_pending(candidate: Mapping[str, Any]) -> None:
        if candidate.get("status") != "pending":
            raise CandidateStateError(
                f"Candidate {candidate.get('id')} is already {candidate.get('status')}"
            )

    def _candidate_lock(self, candidate_id: str):
        if not is_uuid7(candidate_id):
            raise ValueError("candidate ID must be a UUIDv7")
        @contextmanager
        def ordered_lock():
            with file_lock(self.root / "runtime" / "locks" / "writer.lock"):
                with file_lock(
                    self.root / "runtime" / "locks" / "candidates" / f"{candidate_id}.lock"
                ):
                    yield

        return ordered_lock()

    def _project(
        self, candidate_id: str, events: list[Mapping[str, Any]]
    ) -> dict[str, Any]:
        ordered = sorted(
            (event for event in events if event.get("event_type") in CANDIDATE_EVENT_TYPES),
            key=self._event_order_key,
        )
        created = [event for event in ordered if event.get("event_type") == "candidate.created"]
        if not created:
            raise CandidateNotFoundError(f"Candidate not found: {candidate_id}")
        if len(created) != 1:
            raise CandidateIntegrityError(f"Candidate has multiple creation events: {candidate_id}")
        creation = created[0]
        data = creation.get("data")
        if not isinstance(data, Mapping):
            raise CandidateIntegrityError("candidate.created data must be a mapping")
        if creation.get("target") != candidate_id or data.get("candidate_id") != candidate_id:
            raise CandidateIntegrityError("candidate.created ID and target disagree")
        target_document_id = data.get("target_document_id")
        if not is_uuid7(target_document_id):
            raise CandidateIntegrityError("Candidate target_document_id is invalid")
        try:
            claim = validate_claim_proposal(data.get("claim", {}))
        except ValueError as exc:
            raise CandidateIntegrityError(f"Candidate Claim proposal is invalid: {exc}") from exc

        sensitivity = creation.get("sensitivity", "personal")
        if sensitivity not in SENSITIVITIES:
            raise CandidateIntegrityError("Candidate event sensitivity is invalid")

        terminal = [event for event in ordered if event.get("event_type") in TERMINAL_EVENT_TYPES]
        reopened = [event for event in ordered if event.get("event_type") == REOPEN_EVENT_TYPE]
        # A rollback deliberately reopens a previously-promoted Candidate.
        # Multiple terminal events are valid only when each earlier promotion
        # is followed by its exact reopen transition; a second terminal with
        # no intervening reopen remains contradictory.
        state = "pending"
        resolution_event: Mapping[str, Any] | None = None
        for event in ordered:
            event_type = event.get("event_type")
            if event_type == "candidate.rejected":
                if state != "pending":
                    raise CandidateIntegrityError("Candidate rejection is not from a pending state")
                state = "rejected"
                resolution_event = event
            elif event_type == "candidate.promoted":
                if state != "pending":
                    raise CandidateIntegrityError("Candidate has multiple terminal events without rollback")
                state = "promoted"
                resolution_event = event
            elif event_type == REOPEN_EVENT_TYPE:
                if state != "promoted":
                    raise CandidateIntegrityError("Candidate reopen is not after a promotion")
                state = "pending"
                resolution_event = None
        if reopened:
            promoted_manifests = {
                data.get("transaction_id"): data
                for event in ordered
                if event.get("event_type") == "candidate.promoted"
                and isinstance((data := event.get("data")), Mapping)
            }
            for event in reopened:
                data = event.get("data")
                if (
                    not isinstance(data, Mapping)
                    or data.get("candidate_id") != candidate_id
                    or not is_uuid7(data.get("transaction_id"))
                    or not is_uuid7(data.get("claim_id"))
                    or not is_uuid7(data.get("rollback_id"))
                ):
                    raise CandidateIntegrityError("Candidate reopen event data is inconsistent")
                promotion = promoted_manifests.get(data.get("transaction_id"))
                if (
                    not isinstance(promotion, Mapping)
                    or promotion.get("claim_id") != data.get("claim_id")
                ):
                    raise CandidateIntegrityError("Candidate reopen does not match a promotion")
                # Reopening is a projection of a durable Canon rollback, not
                # an independently-authorized Candidate transition.  Resolve
                # the rollback by its target and verify the complete inverse
                # manifest, so a forged candidate.reopened event cannot make
                # a terminal Candidate pending again.
                rollback_id = data.get("rollback_id")
                try:
                    rollback_events = self.canon._events_for(
                        rollback_id, {"canon.rollback-committed"}
                    )
                except (CanonError, OSError, ValueError) as exc:
                    raise CandidateIntegrityError(
                        "Candidate reopen rollback cannot be read safely"
                    ) from exc
                matching_rollbacks = [
                    rollback
                    for rollback in rollback_events
                    if rollback.get("target") == rollback_id
                    and isinstance(rollback.get("data"), Mapping)
                    and rollback["data"].get("transaction_id") == rollback_id
                ]
                if len(matching_rollbacks) != 1:
                    raise CandidateIntegrityError(
                        "Candidate reopen does not match exactly one committed Canon rollback"
                    )
                rollback_data = matching_rollbacks[0]["data"]
                try:
                    source_events = self.canon._events_for(
                        data.get("transaction_id"), {"canon.change-committed"}
                    )
                except (CanonError, OSError, ValueError) as exc:
                    raise CandidateIntegrityError(
                        "Candidate reopen source promotion cannot be read safely"
                    ) from exc
                source_promotions = [
                    source
                    for source in source_events
                    if source.get("target") == data.get("transaction_id")
                    and isinstance(source.get("data"), Mapping)
                    and source["data"].get("transaction_id") == data.get("transaction_id")
                ]
                if len(source_promotions) != 1:
                    raise CandidateIntegrityError(
                        "Candidate reopen does not match exactly one committed Canon promotion"
                    )
                source_data = source_promotions[0]["data"]
                if (
                    rollback_data.get("operation") != "rollback"
                    or rollback_data.get("rollback_of") != data.get("transaction_id")
                    or rollback_data.get("candidate") != candidate_id
                    or rollback_data.get("claim") != data.get("claim_id")
                    or source_data.get("candidate") != candidate_id
                    or source_data.get("claim") != data.get("claim_id")
                    or rollback_data.get("document") != source_data.get("document")
                    or rollback_data.get("path") != source_data.get("path")
                    or rollback_data.get("before") != source_data.get("after")
                    or rollback_data.get("after") != source_data.get("before")
                ):
                    raise CandidateIntegrityError(
                        "Candidate reopen rollback manifest disagrees with Canon promotion"
                    )
        terminal = [resolution_event] if resolution_event is not None else []
        status = "pending"
        resolution: dict[str, Any] | None = None
        if terminal:
            status = "promoted" if terminal[0].get("event_type") == "candidate.promoted" else "rejected"
            terminal_data = terminal[0].get("data", {})
            if not isinstance(terminal_data, Mapping) or terminal_data.get("candidate_id") != candidate_id:
                raise CandidateIntegrityError("Candidate terminal event data is inconsistent")
            terminal_sensitivity = terminal[0].get("sensitivity", "personal")
            if terminal_sensitivity not in SENSITIVITIES:
                raise CandidateIntegrityError("Candidate terminal event sensitivity is invalid")
            if SENSITIVITY_RANK[terminal_sensitivity] < SENSITIVITY_RANK[sensitivity]:
                raise CandidateIntegrityError("Candidate terminal event lowers creation sensitivity")
            if status == "promoted":
                if not is_uuid7(terminal_data.get("transaction_id")):
                    raise CandidateIntegrityError("Candidate promotion transaction_id is invalid")
                if not is_uuid7(terminal_data.get("claim_id")):
                    raise CandidateIntegrityError("Candidate promotion claim_id is invalid")
            elif not isinstance(terminal_data.get("reason"), str) or not terminal_data["reason"].strip():
                raise CandidateIntegrityError("Candidate rejection reason must be non-empty")
            resolution = deepcopy(dict(terminal_data))
        projected = {
            "id": candidate_id,
            "target_document_id": target_document_id,
            "claim": claim,
            "status": status,
            "sensitivity": sensitivity,
            "created_at": creation.get("recorded_at", ""),
            "created_by": creation.get("actor"),
        }
        if resolution is not None:
            projected["resolution"] = resolution
            if status == "promoted":
                projected["transaction_id"] = resolution.get("transaction_id")
                projected["claim_id"] = resolution.get("claim_id")
            else:
                projected["reason"] = resolution.get("reason")
        return projected

    def _events_for(self, candidate_id: str) -> list[Mapping[str, Any]]:
        reader = getattr(self.vault, "events_for", None)
        if callable(reader):
            events = reader(candidate_id, event_types=CANDIDATE_EVENT_TYPES)
            return [event for event in events if isinstance(event, Mapping)]
        return [
            event
            for event in self._all_events()
            if event.get("target") == candidate_id
            and event.get("event_type") in CANDIDATE_EVENT_TYPES
        ]

    def _all_events(self) -> list[Mapping[str, Any]]:
        # Event iteration is authoritative: it rejects malformed, symlinked,
        # FIFO, and tampered records instead of silently dropping them from a
        # Candidate projection.
        try:
            events = [event for event in iter_events(self.vault, verify=True)]
        except (OSError, ValueError) as exc:
            raise CandidateIntegrityError(f"cannot read event log safely: {exc}") from exc
        events.sort(key=self._event_order_key)
        return events

    @staticmethod
    def _event_order_key(event: Mapping[str, Any]) -> tuple[int, str]:
        sequence = event.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise CandidateIntegrityError("Candidate event has an invalid global sequence")
        return sequence, str(event.get("id", ""))


def create_candidate(
    vault: Any,
    target_document_id: str,
    claim: Mapping[str, Any],
    *,
    actor: str,
    sensitivity: str = "personal",
) -> dict[str, Any]:
    return CandidateStore(vault).create(
        target_document_id=target_document_id,
        claim=claim,
        actor=actor,
        sensitivity=sensitivity,
    )


def get_candidate(vault: Any, candidate_id: str) -> dict[str, Any]:
    return CandidateStore(vault).get(candidate_id)


def list_candidates(vault: Any, *, status: str | None = None) -> list[dict[str, Any]]:
    return CandidateStore(vault).list(status=status)


def reject_candidate(
    vault: Any, candidate_id: str, *, actor: str, reason: str
) -> dict[str, Any]:
    return CandidateStore(vault).reject(candidate_id, actor=actor, reason=reason)


def promote_candidate(vault: Any, candidate_id: str, *, actor: str) -> dict[str, Any]:
    return CandidateStore(vault).promote(candidate_id, actor=actor)


def rollback(vault: Any, transaction_id: str, *, actor: str) -> dict[str, Any]:
    return CandidateStore(vault).rollback(transaction_id, actor=actor)
