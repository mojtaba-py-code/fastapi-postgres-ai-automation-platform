"""Stored files leave together with the rows that reference them.

Deleting a project, a dataset or a source removes its uploads and reports by
database cascade; their files are deleted by a job the same transaction
queues (transactional outbox), so a file goes if and only if its row went -
never before the deletion commits, never forgotten when a worker dies.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from nexusflow.domain.shared.outbox import OutboxMessage, TaskName, new_message

FILES_PER_JOB = 200


def file_deletions(org_id: UUID, keys: Sequence[str], *, now: datetime) -> list[OutboxMessage]:
    """The jobs that delete ``keys`` (identifiers only), in bounded batches."""
    return [
        new_message(
            TaskName.DELETE_FILES,
            {"org_id": str(org_id), "keys": list(keys[start : start + FILES_PER_JOB])},
            org_id=org_id,
            now=now,
        )
        for start in range(0, len(keys), FILES_PER_JOB)
    ]
