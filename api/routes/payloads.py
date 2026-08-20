"""Payload endpoints — the statically analysed artefact view.

Every indicator served here is defanged, because the analyser defangs on the
way in and nothing re-fangs it. That is a property of the pipeline, not of this
router, and it is the reason these responses are safe to paste into a ticket.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import ArchRow, Page, PayloadDetail, PayloadOut, PayloadSource
from storage import queries
from storage.db import get_db

router = APIRouter(prefix="/payloads", tags=["payloads"])

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@router.get("", response_model=Page[PayloadOut], summary="List analysed payloads")
def list_payloads(
    db: OrmSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    file_type: str | None = Query(None, description="elf | pe | script-sh | zip | ..."),
    arch: str | None = Query(None, description="mips | arm | x86-64 | ..."),
    behaviour_tag: str | None = Query(None, description="e.g. iot:busybox, downloader:wget"),
    packed_only: bool = Query(False, description="only artefacts flagged likely-packed"),
    sort: str = Query("last_seen"),
) -> Page[PayloadOut]:
    if sort not in queries.PAYLOAD_SORT_FIELDS:
        raise HTTPException(
            400, f"cannot sort by {sort!r}; use one of {list(queries.PAYLOAD_SORT_FIELDS)}"
        )

    rows, total = queries.list_payloads(
        db,
        limit=limit,
        offset=offset,
        file_type=file_type,
        arch=arch,
        behaviour_tag=behaviour_tag,
        packed_only=packed_only,
        sort=sort,
    )
    return Page[PayloadOut](
        items=[PayloadOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/architectures", response_model=list[ArchRow], summary="Payload count per CPU family")
def architectures(db: OrmSession = Depends(get_db)) -> list[ArchRow]:
    """What the operators thought this sensor was.

    IoT botnets ship one build per CPU family and the loader picks by ``uname``,
    so this breakdown reads as a census of what the internet believes is
    listening on these ports.
    """
    return [ArchRow(**row) for row in queries.payload_arch_breakdown(db)]


@router.get("/{sha256}", response_model=PayloadDetail, summary="Payload profile")
def get_payload(
    sha256: str,
    db: OrmSession = Depends(get_db),
    source_limit: int = Query(50, ge=1, le=500),
) -> PayloadDetail:
    if not SHA256_RE.match(sha256):
        raise HTTPException(400, f"{sha256!r} is not a sha256 digest")

    payload = queries.get_payload(db, sha256.lower())
    if payload is None:
        raise HTTPException(404, f"no analysed payload {sha256[:12]}")

    detail = PayloadDetail.model_validate(payload)
    detail.sources = [
        PayloadSource(**row) for row in queries.payload_sources(db, sha256.lower(), source_limit)
    ]
    return detail


__all__ = ["router"]
