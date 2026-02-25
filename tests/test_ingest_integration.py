"""Integration tests for ingest service."""

import io
import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from services.ingest.config import Settings
from services.ingest.database import get_session_factory
from services.ingest.models import Base, Job, JobStatus, Sample
from services.ingest.service import (
    compute_pipeline_hash,
    get_sample_by_sha256,
    list_samples,
    upload_sample,
)


@pytest.fixture(scope="module")
def test_settings():
    """Create test settings with isolated database."""
    return Settings(
        DATABASE_URL="postgresql://scarabeo:scarabeo_dev_password@localhost:5432/scarabeo_test",
        S3_ENDPOINT_URL="http://localhost:9000",
        REDIS_URL="redis://localhost:6379/1",
    )


@pytest.fixture(scope="module")
def db_engine(test_settings):
    """Create test database engine."""
    from sqlalchemy.exc import OperationalError
    engine = create_engine(test_settings.DATABASE_URL)
    try:
        Base.metadata.create_all(engine)
    except OperationalError:
        pytest.skip("PostgreSQL not available")
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture
def db_session(db_engine):
    """Create test database session."""
    Session = sessionmaker(bind=db_engine)
    session = Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def test_tenant_id():
    """Generate unique tenant ID for test isolation."""
    return f"test-tenant-{uuid.uuid4().hex[:8]}"


class TestUploadSample:
    """Integration tests for sample upload."""

    def test_upload_new_sample(self, db_session, test_tenant_id):
        """Test uploading a new sample creates sample and job records."""
        file_content = b"MZ" + b"\x00" * 100  # Minimal PE-like content
        file_obj = io.BytesIO(file_content)

        sample, job = upload_sample(
            db=db_session,
            file_obj=file_obj,
            filename="test.exe",
            tenant_id=test_tenant_id,
            file_size=len(file_content),
        )

        # Verify sample
        assert sample.tenant_id == test_tenant_id
        assert sample.filename == "test.exe"
        assert sample.file_type == "pe"
        assert sample.size_bytes == len(file_content)

        # Verify job
        assert job.sample_id == sample.id
        assert job.pipeline_name == "triage"
        assert job.status == JobStatus.QUEUED

    def test_upload_idempotency(self, db_session, test_tenant_id):
        """Test uploading same file twice creates one sample, two jobs."""
        file_content = b"test content for idempotency"
        filename = "idempotent_test.bin"

        # First upload
        file_obj1 = io.BytesIO(file_content)
        sample1, job1 = upload_sample(
            db=db_session,
            file_obj=file_obj1,
            filename=filename,
            tenant_id=test_tenant_id,
            file_size=len(file_content),
        )

        # Second upload (same content)
        file_obj2 = io.BytesIO(file_content)
        sample2, job2 = upload_sample(
            db=db_session,
            file_obj=file_obj2,
            filename=filename,
            tenant_id=test_tenant_id,
            file_size=len(file_content),
        )

        # Same sample, different jobs
        assert sample1.id == sample2.id
        assert job1.id != job2.id
        assert job1.sample_id == job2.sample_id

        # Verify only one sample exists
        samples = db_session.execute(
            select(Sample).where(Sample.tenant_id == test_tenant_id)
        ).scalars().all()
        assert len(samples) == 1

    def test_upload_different_tenants_same_hash(self, db_session):
        """Test same file uploaded by different tenants creates separate samples."""
        file_content = b"shared content"
        tenant1 = f"tenant-{uuid.uuid4().hex[:8]}"
        tenant2 = f"tenant-{uuid.uuid4().hex[:8]}"

        file_obj1 = io.BytesIO(file_content)
        sample1, _ = upload_sample(
            db=db_session,
            file_obj=file_obj1,
            filename="shared.bin",
            tenant_id=tenant1,
            file_size=len(file_content),
        )

        file_obj2 = io.BytesIO(file_content)
        sample2, _ = upload_sample(
            db=db_session,
            file_obj=file_obj2,
            filename="shared.bin",
            tenant_id=tenant2,
            file_size=len(file_content),
        )

        # Different samples (tenant isolation)
        assert sample1.id != sample2.id
        assert sample1.sha256 == sample2.sha256  # Same hash


class TestGetSample:
    """Integration tests for sample retrieval."""

    def test_get_sample_by_sha256(self, db_session, test_tenant_id):
        """Test retrieving sample by SHA256."""
        file_content = b"test retrieval content"
        file_obj = io.BytesIO(file_content)

        sample, _ = upload_sample(
            db=db_session,
            file_obj=file_obj,
            filename="retrieval.bin",
            tenant_id=test_tenant_id,
            file_size=len(file_content),
        )

        # Compute expected SHA256
        import hashlib
        expected_sha256 = hashlib.sha256(file_content).hexdigest()

        # Retrieve
        retrieved = get_sample_by_sha256(
            db=db_session,
            sha256=expected_sha256,
            tenant_id=test_tenant_id,
        )

        assert retrieved is not None
        assert retrieved.id == sample.id

    def test_get_sample_wrong_tenant(self, db_session):
        """Test cannot retrieve sample with wrong tenant ID."""
        file_content = b"tenant isolation test"
        tenant1 = f"tenant-{uuid.uuid4().hex[:8]}"
        tenant2 = f"tenant-{uuid.uuid4().hex[:8]}"

        file_obj = io.BytesIO(file_content)
        sample, _ = upload_sample(
            db=db_session,
            file_obj=file_obj,
            filename="isolated.bin",
            tenant_id=tenant1,
            file_size=len(file_content),
        )

        import hashlib
        sha256 = hashlib.sha256(file_content).hexdigest()

        # Try to retrieve with different tenant
        retrieved = get_sample_by_sha256(
            db=db_session,
            sha256=sha256,
            tenant_id=tenant2,
        )

        assert retrieved is None


class TestListSamples:
    """Integration tests for sample listing."""

    def test_list_samples_pagination(self, db_session, test_tenant_id):
        """Test listing samples with pagination."""
        # Upload multiple samples
        for i in range(25):
            file_content = f"sample {i}".encode()
            file_obj = io.BytesIO(file_content)
            upload_sample(
                db=db_session,
                file_obj=file_obj,
                filename=f"sample_{i}.bin",
                tenant_id=test_tenant_id,
                file_size=len(file_content),
            )

        # First page
        samples1, total1 = list_samples(
            db=db_session,
            tenant_id=test_tenant_id,
            page=1,
            per_page=20,
        )
        assert len(samples1) == 20
        assert total1 == 25

        # Second page
        samples2, total2 = list_samples(
            db=db_session,
            tenant_id=test_tenant_id,
            page=2,
            per_page=20,
        )
        assert len(samples2) == 5
        assert total2 == 25

    def test_list_samples_ordering(self, db_session, test_tenant_id):
        """Test samples are ordered by created_at desc, sha256."""
        # Upload samples with slight delays
        for i in range(5):
            file_content = f"order test {i}".encode()
            file_obj = io.BytesIO(file_content)
            upload_sample(
                db=db_session,
                file_obj=file_obj,
                filename=f"order_{i}.bin",
                tenant_id=test_tenant_id,
                file_size=len(file_content),
            )

        samples, _ = list_samples(
            db=db_session,
            tenant_id=test_tenant_id,
            page=1,
            per_page=10,
        )

        # Verify ordering (newest first)
        for i in range(len(samples) - 1):
            assert samples[i].created_at >= samples[i + 1].created_at


class TestPipelineHash:
    """Tests for pipeline hash computation."""

    def test_compute_pipeline_hash(self):
        """Test pipeline hash is deterministic."""
        from pathlib import Path
        pipeline_path = Path(__file__).parent.parent.parent / "pipelines" / "triage.yaml"

        hash1 = compute_pipeline_hash(pipeline_path)
        hash2 = compute_pipeline_hash(pipeline_path)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length

    def test_pipeline_hash_changes_with_content(self):
        """Test pipeline hash changes when file content changes."""
        import tempfile
        import hashlib

        # Create temp file with content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("name: test\n")
            temp_path = f.name

        try:
            hash1 = compute_pipeline_hash(temp_path)

            # Modify content
            with open(temp_path, 'w') as f:
                f.write("name: test\nversion: 1.0\n")

            hash2 = compute_pipeline_hash(temp_path)

            assert hash1 != hash2
        finally:
            os.unlink(temp_path)
