"""Sample fingerprint persistence and similarity querying.

Public API
----------
upsert_fingerprint(db, sha256, tenant_id, *, tlsh, ssdeep, imphash,
                   strings_hash, extra) -> SampleFingerprint
    Idempotently insert or update a sample's fingerprint row.

get_fingerprint(db, sha256, tenant_id) -> SampleFingerprint | None
    Retrieve the fingerprint for a single sample.

find_similar(db, sha256, tenant_id, *, algorithm, limit) -> list[dict]
    Return samples that are similar to the given sha256 under the
    specified algorithm.  Results are sorted by score descending.

Design note
-----------
All imports from ``services.*`` are deferred inside functions.  This keeps
``import scarabeo.fingerprint`` lightweight — no boto3 / SQLAlchemy engine
initialisation happens at import time — and avoids circular-import issues
caused by ``services/ingest/__init__.py`` eagerly importing the full app.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Supported algorithms exposed through the API.
SUPPORTED_ALGORITHMS = frozenset({"tlsh", "ssdeep", "imphash"})

# Similarity thresholds (mirrors services/worker/clustering.py defaults).
# Defined here so fingerprint.py has no top-level dependency on clustering.py.
_TLSH_THRESHOLD = 30    # TLSH distance ≤ this → similar (lower = more similar)
_SSDEEP_THRESHOLD = 90  # ssdeep score  ≥ this → similar (higher = more similar)

# Maximum number of rows fetched for bulk comparison (tlsh / ssdeep).
_CANDIDATE_LIMIT = 500


def upsert_fingerprint(
    db: Session,
    sha256: str,
    tenant_id: str,
    *,
    tlsh: "str | None" = None,
    ssdeep: "str | None" = None,
    imphash: "str | None" = None,
    strings_hash: "str | None" = None,
    extra: "dict | None" = None,
) -> "Any":
    """
    Idempotently insert or update a sample's fingerprint record.

    On conflict (tenant_id, sha256) the row is updated in place.  Only
    keyword arguments explicitly passed (i.e. not ``None``) overwrite
    existing column values, so callers can update a single hash without
    clearing the others.

    Args:
        db:           Open SQLAlchemy session (will be committed on success).
        sha256:       Sample SHA256 (64 hex chars).
        tenant_id:    Tenant identifier.
        tlsh:         TLSH hash string (optional).
        ssdeep:       ssdeep fuzzy hash string (optional).
        imphash:      PE import hash — MD5 of normalised import table (optional).
        strings_hash: SHA256 of sorted printable strings (optional).
        extra:        Arbitrary JSON metadata, e.g. file_type, size_bytes (optional).

    Returns:
        The upserted ``SampleFingerprint`` row.
    """
    from services.ingest.models import SampleFingerprint

    now = datetime.now(timezone.utc)

    # Build the column map for both INSERT and UPDATE.  Always refresh
    # updated_at; only include hash columns when the caller supplied a value.
    values: dict[str, Any] = {
        "tenant_id": tenant_id,
        "sha256": sha256,
        "updated_at": now,
    }
    if tlsh is not None:
        values["tlsh"] = tlsh
    if ssdeep is not None:
        values["ssdeep"] = ssdeep
    if imphash is not None:
        values["imphash"] = imphash
    if strings_hash is not None:
        values["strings_hash"] = strings_hash
    if extra is not None:
        values["extra"] = extra

    # Columns to update on conflict — everything except the PK columns.
    update_set = {k: v for k, v in values.items() if k not in ("tenant_id", "sha256")}

    stmt = (
        pg_insert(SampleFingerprint)
        .values(**values, created_at=now)
        .on_conflict_do_update(
            index_elements=["tenant_id", "sha256"],
            set_=update_set,
        )
        .returning(SampleFingerprint)
    )
    row = db.execute(stmt).scalar_one()
    db.commit()

    logger.debug(
        "Upserted fingerprint for %s (tenant=%s)", sha256[:16], tenant_id
    )
    return row


def get_fingerprint(
    db: Session,
    sha256: str,
    tenant_id: str,
) -> "Any | None":
    """
    Retrieve the fingerprint record for a single sample.

    Args:
        db:        Open SQLAlchemy session.
        sha256:    Sample SHA256.
        tenant_id: Tenant identifier.

    Returns:
        ``SampleFingerprint`` row or ``None`` if no record exists.
    """
    from services.ingest.models import SampleFingerprint

    return db.execute(
        select(SampleFingerprint).where(
            SampleFingerprint.tenant_id == tenant_id,
            SampleFingerprint.sha256 == sha256,
        )
    ).scalar_one_or_none()


def find_similar(
    db: Session,
    sha256: str,
    tenant_id: str,
    *,
    algorithm: str = "tlsh",
    limit: int = 20,
) -> list[dict]:
    """
    Find samples similar to the given sha256 under the specified algorithm.

    Algorithm behaviour
    -------------------
    ``imphash``
        Exact match on the PE import hash.  Uses the
        ``ix_sample_fingerprints_imphash`` index — O(log n).  Score is
        always 100 for a match.

    ``tlsh``
        Locality-sensitive hash distance.  Loads up to
        ``_CANDIDATE_LIMIT`` recent fingerprints for the tenant and
        computes pairwise distances in Python.  Matches where distance
        ≤ 30 are returned; score is ``100 − distance``.

    ``ssdeep``
        Fuzzy hash match score.  Same bulk-comparison approach as TLSH.
        Matches where score ≥ 90 are returned.

    Args:
        db:        Open SQLAlchemy session.
        sha256:    SHA256 of the reference sample.
        tenant_id: Tenant identifier (results are always tenant-scoped).
        algorithm: One of ``"tlsh"``, ``"ssdeep"``, ``"imphash"``.
        limit:     Maximum number of results to return (1–100).

    Returns:
        List of dicts ``{"sha256": str, "algorithm": str, "score": int}``,
        sorted by score descending, excluding the query sample itself.

    Raises:
        ValueError: If ``algorithm`` is not a supported value.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. "
            f"Choose from: {sorted(SUPPORTED_ALGORITHMS)}"
        )

    from services.ingest.models import SampleFingerprint
    from services.worker.clustering import (
        compute_imphash_match,
        compute_ssdeep_score,
        compute_tlsh_distance,
    )

    ref = get_fingerprint(db, sha256, tenant_id)
    if ref is None:
        logger.debug(
            "No fingerprint stored for %s — cannot compute similarity", sha256[:16]
        )
        return []

    ref_hash: "str | None" = getattr(ref, algorithm)
    if not ref_hash:
        logger.debug(
            "Fingerprint for %s has no %s hash", sha256[:16], algorithm
        )
        return []

    # ── imphash: exact-match index scan ─────────────────────────────────────
    if algorithm == "imphash":
        rows = db.execute(
            select(SampleFingerprint).where(
                SampleFingerprint.tenant_id == tenant_id,
                SampleFingerprint.imphash == ref_hash,
                SampleFingerprint.sha256 != sha256,
            )
        ).scalars().all()
        return [
            {"sha256": r.sha256, "algorithm": "imphash", "score": 100}
            for r in rows[:limit]
        ]

    # ── tlsh / ssdeep: load candidates, compute distances in Python ─────────
    candidates = db.execute(
        select(SampleFingerprint)
        .where(
            SampleFingerprint.tenant_id == tenant_id,
            SampleFingerprint.sha256 != sha256,
        )
        .order_by(SampleFingerprint.created_at.desc())
        .limit(_CANDIDATE_LIMIT)
    ).scalars().all()

    results: list[dict] = []

    for candidate in candidates:
        cand_hash: "str | None" = getattr(candidate, algorithm)
        if not cand_hash:
            continue

        if algorithm == "tlsh":
            distance = compute_tlsh_distance(ref_hash, cand_hash)
            if distance <= _TLSH_THRESHOLD:
                results.append(
                    {
                        "sha256": candidate.sha256,
                        "algorithm": "tlsh",
                        "score": 100 - distance,
                    }
                )
        else:  # ssdeep
            score = compute_ssdeep_score(ref_hash, cand_hash)
            if score >= _SSDEEP_THRESHOLD:
                results.append(
                    {
                        "sha256": candidate.sha256,
                        "algorithm": "ssdeep",
                        "score": score,
                    }
                )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:limit]
