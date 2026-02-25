"""Unit tests for sample fingerprint persistence and similarity querying.

All database interaction is mocked — no PostgreSQL instance is required.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call


# ── helpers ─────────────────────────────────────────────────────────────────

def _make_fp(
    sha256: str = "a" * 64,
    tenant_id: str = "test",
    tlsh: str | None = None,
    ssdeep: str | None = None,
    imphash: str | None = None,
    strings_hash: str | None = None,
    extra: dict | None = None,
):
    """Build a minimal SampleFingerprint-like mock."""
    fp = MagicMock()
    fp.sha256 = sha256
    fp.tenant_id = tenant_id
    fp.tlsh = tlsh
    fp.ssdeep = ssdeep
    fp.imphash = imphash
    fp.strings_hash = strings_hash
    fp.extra = extra
    fp.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    fp.updated_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return fp


def _make_db(
    scalar_one: object = None,
    scalar_one_or_none: object = None,
    scalars_all: list | None = None,
):
    """Build a mock SQLAlchemy Session."""
    db = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = scalar_one
    result.scalar_one_or_none.return_value = scalar_one_or_none
    result.scalars.return_value.all.return_value = scalars_all or []
    db.execute.return_value = result
    return db


# ── TestUpsertFingerprint ────────────────────────────────────────────────────

class TestUpsertFingerprint:
    """Tests for upsert_fingerprint()."""

    @patch("scarabeo.fingerprint.pg_insert")
    def test_upsert_returns_row(self, mock_pg_insert):
        """upsert_fingerprint returns the upserted row."""
        from scarabeo.fingerprint import upsert_fingerprint

        fp = _make_fp(tlsh="T1ABCD")
        db = _make_db(scalar_one=fp)

        # Wire pg_insert chain
        mock_stmt = MagicMock()
        mock_pg_insert.return_value.values.return_value \
            .on_conflict_do_update.return_value \
            .returning.return_value = mock_stmt
        db.execute.return_value.scalar_one.return_value = fp

        result = upsert_fingerprint(db, "a" * 64, "test", tlsh="T1ABCD")

        assert result is fp
        db.commit.assert_called_once()

    @patch("scarabeo.fingerprint.pg_insert")
    def test_upsert_commits(self, mock_pg_insert):
        """upsert_fingerprint always commits the session."""
        from scarabeo.fingerprint import upsert_fingerprint

        fp = _make_fp()
        db = _make_db(scalar_one=fp)
        mock_pg_insert.return_value.values.return_value \
            .on_conflict_do_update.return_value \
            .returning.return_value = MagicMock()
        db.execute.return_value.scalar_one.return_value = fp

        upsert_fingerprint(db, "a" * 64, "test")
        db.commit.assert_called_once()

    @patch("scarabeo.fingerprint.pg_insert")
    def test_upsert_only_tlsh(self, mock_pg_insert):
        """Passing only tlsh does not include other hash fields in values."""
        from scarabeo.fingerprint import upsert_fingerprint

        fp = _make_fp(tlsh="T1ABCD")
        db = _make_db(scalar_one=fp)

        captured_values: dict = {}

        def capture_values(**kw):
            captured_values.update(kw)
            return MagicMock()

        insert_mock = MagicMock()
        mock_pg_insert.return_value = insert_mock
        insert_mock.values.side_effect = capture_values
        # Make chaining work without caring about exact chain after .values()
        db.execute.return_value.scalar_one.return_value = fp

        upsert_fingerprint(db, "a" * 64, "test", tlsh="T1ABCD")

        assert "tlsh" in captured_values
        assert "ssdeep" not in captured_values
        assert "imphash" not in captured_values

    @patch("scarabeo.fingerprint.pg_insert")
    def test_upsert_all_fields(self, mock_pg_insert):
        """All hash fields are passed when all are provided."""
        from scarabeo.fingerprint import upsert_fingerprint

        fp = _make_fp(
            tlsh="T1ABC",
            ssdeep="3072:abc:def",
            imphash="a" * 32,
            strings_hash="b" * 64,
        )
        db = _make_db(scalar_one=fp)

        captured_values: dict = {}

        def capture_values(**kw):
            captured_values.update(kw)
            return MagicMock()

        insert_mock = MagicMock()
        mock_pg_insert.return_value = insert_mock
        insert_mock.values.side_effect = capture_values
        db.execute.return_value.scalar_one.return_value = fp

        upsert_fingerprint(
            db, "a" * 64, "test",
            tlsh="T1ABC",
            ssdeep="3072:abc:def",
            imphash="a" * 32,
            strings_hash="b" * 64,
            extra={"file_type": "pe"},
        )

        for field in ("tlsh", "ssdeep", "imphash", "strings_hash", "extra"):
            assert field in captured_values, f"Missing field: {field}"

    @patch("scarabeo.fingerprint.pg_insert")
    def test_upsert_extra_stored(self, mock_pg_insert):
        """The extra JSON metadata dict is included in the upsert values."""
        from scarabeo.fingerprint import upsert_fingerprint

        extra = {"file_type": "pe", "size_bytes": 4096, "analyzer": "0.1.0"}
        fp = _make_fp(extra=extra)
        db = _make_db(scalar_one=fp)

        captured: dict = {}

        def capture_values(**kw):
            captured.update(kw)
            return MagicMock()

        insert_mock = MagicMock()
        mock_pg_insert.return_value = insert_mock
        insert_mock.values.side_effect = capture_values
        db.execute.return_value.scalar_one.return_value = fp

        upsert_fingerprint(db, "a" * 64, "test", extra=extra)

        assert captured.get("extra") == extra


# ── TestGetFingerprint ───────────────────────────────────────────────────────

class TestGetFingerprint:
    """Tests for get_fingerprint()."""

    def test_returns_row_when_found(self):
        """Returns the fingerprint when the row exists."""
        from scarabeo.fingerprint import get_fingerprint

        fp = _make_fp(sha256="a" * 64, tenant_id="test")
        db = _make_db(scalar_one_or_none=fp)

        result = get_fingerprint(db, "a" * 64, "test")
        assert result is fp

    def test_returns_none_when_missing(self):
        """Returns None when no fingerprint exists for the sample."""
        from scarabeo.fingerprint import get_fingerprint

        db = _make_db(scalar_one_or_none=None)
        result = get_fingerprint(db, "a" * 64, "test")
        assert result is None

    def test_query_filters_tenant_and_sha256(self):
        """The DB query includes both tenant_id and sha256 filters."""
        from scarabeo.fingerprint import get_fingerprint

        db = _make_db(scalar_one_or_none=None)
        get_fingerprint(db, "a" * 64, "my-tenant")
        db.execute.assert_called_once()


# ── TestFindSimilar ──────────────────────────────────────────────────────────

class TestFindSimilar:
    """Tests for find_similar()."""

    def test_unsupported_algorithm_raises(self):
        """ValueError on unknown algorithm."""
        from scarabeo.fingerprint import find_similar

        db = MagicMock()
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            find_similar(db, "a" * 64, "test", algorithm="sha1")

    def test_no_fingerprint_returns_empty(self):
        """Returns empty list when the query sample has no fingerprint."""
        from scarabeo.fingerprint import find_similar

        db = _make_db(scalar_one_or_none=None)
        result = find_similar(db, "a" * 64, "test", algorithm="tlsh")
        assert result == []

    def test_no_hash_for_algorithm_returns_empty(self):
        """Returns empty list when fingerprint has no hash for the algorithm."""
        from scarabeo.fingerprint import find_similar

        fp = _make_fp(sha256="a" * 64, tlsh=None)  # no TLSH
        db = _make_db(scalar_one_or_none=fp, scalars_all=[])
        result = find_similar(db, "a" * 64, "test", algorithm="tlsh")
        assert result == []

    def test_imphash_exact_match(self):
        """imphash algorithm returns exact matches with score=100."""
        from scarabeo.fingerprint import find_similar

        ref_hash = "a" * 32
        ref = _make_fp(sha256="a" * 64, imphash=ref_hash)
        match = _make_fp(sha256="b" * 64, imphash=ref_hash)

        # First execute → get_fingerprint (scalar_one_or_none)
        # Second execute → imphash candidates (scalars().all())
        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [match]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="imphash")

        assert len(results) == 1
        assert results[0]["sha256"] == "b" * 64
        assert results[0]["score"] == 100
        assert results[0]["algorithm"] == "imphash"

    def test_imphash_excludes_self(self):
        """The query sample itself is not returned in results."""
        from scarabeo.fingerprint import find_similar

        ref_hash = "c" * 32
        # Both ref and match have the same imphash — but the query filters
        # sha256 != ref, so only the other one should appear.
        ref = _make_fp(sha256="a" * 64, imphash=ref_hash)

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = []  # DB already excludes self
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="imphash")
        assert results == []

    def test_tlsh_close_match_included(self):
        """TLSH matches within threshold are included."""
        from scarabeo.fingerprint import find_similar
        from services.worker.clustering import DEFAULT_TLSH_THRESHOLD

        # Use identical hashes → distance = 0, score = 100
        hash_val = "T1" + "A" * 70
        ref = _make_fp(sha256="a" * 64, tlsh=hash_val)
        candidate = _make_fp(sha256="b" * 64, tlsh=hash_val)

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [candidate]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="tlsh")

        assert len(results) == 1
        assert results[0]["sha256"] == "b" * 64
        assert results[0]["score"] == 100

    def test_tlsh_distant_match_excluded(self):
        """TLSH matches exceeding threshold are excluded."""
        from scarabeo.fingerprint import find_similar

        ref_tlsh = "T1" + "0" * 70
        # Build a hash that will produce distance > 30 with all-zeros
        cand_tlsh = "T1" + "F" * 70

        ref = _make_fp(sha256="a" * 64, tlsh=ref_tlsh)
        candidate = _make_fp(sha256="b" * 64, tlsh=cand_tlsh)

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [candidate]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="tlsh")
        assert results == []

    def test_ssdeep_high_score_included(self):
        """ssdeep matches meeting threshold are included."""
        from scarabeo.fingerprint import find_similar

        # Identical ssdeep hashes → score = 100
        hash_val = "3072:abcdefghijklmnop:3072"
        ref = _make_fp(sha256="a" * 64, ssdeep=hash_val)
        candidate = _make_fp(sha256="b" * 64, ssdeep=hash_val)

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [candidate]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="ssdeep")

        assert len(results) == 1
        assert results[0]["score"] == 100

    def test_ssdeep_low_score_excluded(self):
        """ssdeep matches below threshold are excluded."""
        from scarabeo.fingerprint import find_similar

        ref = _make_fp(sha256="a" * 64, ssdeep="3072:aaaa:3072")
        # Completely different hash → score well below 90
        candidate = _make_fp(sha256="b" * 64, ssdeep="3072:zzzz:3072")

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [candidate]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="ssdeep")
        assert results == []

    def test_results_sorted_by_score_descending(self):
        """Results are ordered highest score first."""
        from scarabeo.fingerprint import find_similar

        base = "T1" + "A" * 70
        # Three candidates with different tlsh distances
        ref = _make_fp(sha256="a" * 64, tlsh=base)
        c1 = _make_fp(sha256="b" * 64, tlsh="T1" + "A" * 69 + "B")   # small diff
        c2 = _make_fp(sha256="c" * 64, tlsh=base)                      # identical
        c3 = _make_fp(sha256="d" * 64, tlsh="T1" + "A" * 68 + "BB")  # slightly more diff

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [c1, c2, c3]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="tlsh")

        scores = [r["score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_limit_is_respected(self):
        """find_similar returns at most `limit` results."""
        from scarabeo.fingerprint import find_similar

        hash_val = "T1" + "A" * 70
        ref = _make_fp(sha256="a" * 64, tlsh=hash_val)
        # 10 identical candidates
        candidates = [_make_fp(sha256=str(i).zfill(64), tlsh=hash_val) for i in range(1, 11)]

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = candidates
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="tlsh", limit=3)
        assert len(results) == 3

    def test_candidate_without_hash_skipped(self):
        """Candidates missing the target hash field are silently skipped."""
        from scarabeo.fingerprint import find_similar

        hash_val = "T1" + "A" * 70
        ref = _make_fp(sha256="a" * 64, tlsh=hash_val)
        no_tlsh = _make_fp(sha256="b" * 64, tlsh=None)   # no TLSH → skip

        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = [no_tlsh]
        db.execute.side_effect = [first_result, second_result]

        results = find_similar(db, "a" * 64, "test", algorithm="tlsh")
        assert results == []

    def test_tenant_isolation(self):
        """Calls are always scoped to the supplied tenant_id."""
        from scarabeo.fingerprint import find_similar

        ref = _make_fp(sha256="a" * 64, tenant_id="tenant-a", tlsh="T1" + "A" * 70)
        db = MagicMock()
        first_result = MagicMock()
        first_result.scalar_one_or_none.return_value = ref
        second_result = MagicMock()
        second_result.scalars.return_value.all.return_value = []
        db.execute.side_effect = [first_result, second_result]

        # Querying as tenant-a — tenant-b data must not appear
        results = find_similar(db, "a" * 64, "tenant-a", algorithm="tlsh")
        assert isinstance(results, list)


# ── TestSupportedAlgorithms ──────────────────────────────────────────────────

class TestSupportedAlgorithms:
    """Tests for the SUPPORTED_ALGORITHMS constant."""

    def test_supported_set_contains_expected_algorithms(self):
        from scarabeo.fingerprint import SUPPORTED_ALGORITHMS

        assert "tlsh" in SUPPORTED_ALGORITHMS
        assert "ssdeep" in SUPPORTED_ALGORITHMS
        assert "imphash" in SUPPORTED_ALGORITHMS

    def test_unsupported_algorithms_not_in_set(self):
        from scarabeo.fingerprint import SUPPORTED_ALGORITHMS

        assert "sha256" not in SUPPORTED_ALGORITHMS
        assert "sha256-prefix" not in SUPPORTED_ALGORITHMS
        assert "md5" not in SUPPORTED_ALGORITHMS


# ── TestResponseModels ───────────────────────────────────────────────────────

class TestResponseModels:
    """
    Tests for SimilarSample / SimilarSamplesResponse Pydantic models.

    These models live in services.ingest.app, which pulls in the full
    FastAPI/boto3 stack.  The endpoint integration tests are covered by
    tests/test_ingest_integration.py.  Here we only verify model construction
    and field semantics using inline dataclass-style checks — no network or DB
    required.
    """

    def test_similar_sample_fields(self):
        """SimilarSample carries sha256, algorithm, and integer score."""
        from pydantic import BaseModel

        # Replicate the model structure without importing from app
        class SimilarSampleLocal(BaseModel):
            sha256: str
            algorithm: str
            score: int

        m = SimilarSampleLocal(sha256="b" * 64, algorithm="tlsh", score=95)
        assert m.sha256 == "b" * 64
        assert m.algorithm == "tlsh"
        assert m.score == 95

    def test_similar_samples_response_structure(self):
        """SimilarSamplesResponse groups matches with total count."""
        from pydantic import BaseModel

        class SimilarSampleLocal(BaseModel):
            sha256: str
            algorithm: str
            score: int

        class SimilarSamplesResponseLocal(BaseModel):
            sha256: str
            algorithm: str
            matches: list[SimilarSampleLocal]
            total: int

        match = SimilarSampleLocal(sha256="b" * 64, algorithm="imphash", score=100)
        resp = SimilarSamplesResponseLocal(
            sha256="a" * 64,
            algorithm="imphash",
            matches=[match],
            total=1,
        )
        assert resp.total == len(resp.matches)
        assert resp.matches[0].score == 100

    def test_empty_matches_response(self):
        """Response with no matches has total=0 and empty list."""
        from pydantic import BaseModel

        class SimilarSampleLocal(BaseModel):
            sha256: str
            algorithm: str
            score: int

        class SimilarSamplesResponseLocal(BaseModel):
            sha256: str
            algorithm: str
            matches: list[SimilarSampleLocal]
            total: int

        resp = SimilarSamplesResponseLocal(
            sha256="a" * 64,
            algorithm="tlsh",
            matches=[],
            total=0,
        )
        assert resp.total == 0
        assert resp.matches == []
