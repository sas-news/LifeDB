from __future__ import annotations

from pathlib import Path
from collections.abc import Iterable

from .evidence import (
    append_event as append_evidence_event,
    effective_evidence as project_effective_evidence,
    find_evidence_path,
    iter_events,
    load_evidence as read_evidence,
)
from .storage import file_lock
from ._json_types import JSONMapping, JSONValue
from ._vault_protocols import VaultCollaborator


class VaultEvidenceMixin:
    def evidence_path(self: VaultCollaborator, evidence_id: str) -> Path | None:
        return find_evidence_path(self, evidence_id)

    def load_evidence(self: VaultCollaborator, evidence_id: str, *, verify: bool = True) -> JSONMapping | None:
        return read_evidence(self, evidence_id, verify=verify)

    def append_event(
        self: VaultCollaborator,
        event_type: str,
        *,
        actor: str,
        data: JSONValue | None = None,
        target: str | None = None,
        sensitivity: str = "personal",
        category: str | None = None,
        recorded_at: str | None = None,
    ) -> JSONMapping:
        with file_lock(self.root / "runtime" / "locks" / "writer.lock", boundary=self.root):
            self._require_current_metadata()
            event = append_evidence_event(
                self, event_type, actor=actor, data=data, target=target,
                sensitivity=sensitivity, category=category, recorded_at=recorded_at,
            )
        self.mark_index_dirty(reason="evidence-event", record_id=event["id"])
        return event

    def events_for(
        self,
        target: str,
        *,
        event_types: Iterable[str] | None = None,
        category: str | None = None,
        verify: bool = True,
    ) -> list[JSONMapping]:
        return list(iter_events(self, target=target, event_types=event_types, category=category, verify=verify))

    def effective_evidence(self: VaultCollaborator, evidence_id: str, *, verify: bool = True) -> JSONMapping | None:
        return project_effective_evidence(self, evidence_id, verify=verify)
