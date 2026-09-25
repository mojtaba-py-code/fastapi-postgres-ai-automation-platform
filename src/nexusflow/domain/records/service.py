"""Change detection over pending record versions (idempotent, resumable)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from nexusflow.core.clock import Clock
from nexusflow.core.ids import uuid7
from nexusflow.domain.automation.events import EventType, event_message
from nexusflow.domain.catalog.service import get_dataset
from nexusflow.domain.records.detection import diff_versions
from nexusflow.domain.records.model import Change, Significance
from nexusflow.domain.records.sealing import seal_diff
from nexusflow.domain.shared.security import SecretCipher
from nexusflow.domain.shared.unit_of_work import TenantScope, UnitOfWork, UnitOfWorkFactory


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    dataset_id: UUID
    versions_processed: int
    changes_created: int
    max_significance: Significance | None
    analyze: bool


class ChangeDetectionService:
    def __init__(
        self,
        *,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        cipher: SecretCipher,
        batch_size: int = 1000,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._cipher = cipher
        self._batch = batch_size

    async def detect(self, *, org_id: UUID, dataset_id: UUID) -> DetectionOutcome:
        """Diff one batch of undiffed versions. Safe to call concurrently
        (``SKIP LOCKED``) and repeatedly (unique ``(record_id, to_version)``)."""
        now = self._clock.now()
        async with self._uow_factory(TenantScope.system(org_id)) as uow:
            dataset = await get_dataset(uow, org_id, dataset_id)
            spec = dataset.spec
            versions = await uow.data.records.pending_versions(dataset_id, limit=self._batch)
            if not versions:
                return DetectionOutcome(dataset_id, 0, 0, None, analyze=False)
            previous = await uow.data.records.previous_versions(
                (v.record_id, v.version - 1) for v in versions
            )
            keys = await uow.data.records.keys_for(list({v.record_id for v in versions}))
            candidates: list[Change] = []
            for version in versions:
                before = previous.get((version.record_id, version.version - 1))
                before_data = None if before is None or before.is_deletion else before.data
                after_data = None if version.is_deletion else version.data
                detected = diff_versions(spec, before_data, after_data)
                if detected is None:
                    continue
                candidates.append(
                    Change(
                        id=uuid7(),
                        org_id=org_id,
                        dataset_id=dataset_id,
                        record_id=version.record_id,
                        record_key=keys.get(version.record_id, "")[:512],
                        run_id=version.run_id,
                        change_type=detected.change_type,
                        from_version=version.version - 1 if version.version > 1 else None,
                        to_version=version.version,
                        # Versions load opened; the diff of sensitive fields is sealed.
                        diff=seal_diff(
                            self._cipher,
                            detected.diff,
                            spec.sensitive_fields,
                            org_id=org_id,
                            dataset_id=dataset_id,
                            record_id=version.record_id,
                        ),
                        significance=detected.significance,
                        score=detected.score,
                        detected_at=now,
                    )
                )
            inserted = await uow.data.changes.add_new(candidates)
            await uow.data.records.mark_diffed([v.id for v in versions])
            max_level = max((c.significance for c in inserted), key=lambda s: s.rank, default=None)
            analyze = await _analysis_requested(
                uow, org_id, {v.run_id for v in versions if v.run_id}
            )
            if inserted:
                await uow.outbox.add(
                    event_message(
                        EventType.CHANGES_DETECTED,
                        org_id=org_id,
                        payload={
                            "dataset_id": str(dataset_id),
                            "changes": len(inserted),
                            "max_significance": max_level.value if max_level else None,
                            "analyze": analyze,
                        },
                        now=now,
                    )
                )
            await uow.commit()
        return DetectionOutcome(dataset_id, len(versions), len(inserted), max_level, analyze)


async def _analysis_requested(uow: UnitOfWork, org_id: UUID, run_ids: set[UUID]) -> bool:
    """AI analysis runs for data collected by workflows that opted into it."""
    for run_id in list(run_ids)[:50]:
        run = await uow.data.runs.get(org_id, run_id)
        if run is None or run.workflow_run_id is None:
            continue
        workflow_run = await uow.data.workflow_runs.get(org_id, run.workflow_run_id)
        if workflow_run is None:
            continue
        workflow = await uow.data.workflows.get(org_id, workflow_run.workflow_id)
        if workflow is not None and workflow.analyze:
            return True
    return False
