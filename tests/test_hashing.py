"""Unit tests for hashing module."""

import io
from services.ingest.hashing import compute_hashes_bytes, compute_hashes_streaming, validate_sha256


class TestComputeHashesBytes:
    """Tests for compute_hashes_bytes function."""

    def test_empty_bytes(self):
        """Test hashing empty bytes."""
        hashes = compute_hashes_bytes(b"")
        assert hashes.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert hashes.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert hashes.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_known_string(self):
        """Test hashing known string for determinism."""
        data = b"hello world"
        hashes = compute_hashes_bytes(data)
        assert hashes.md5 == "5eb63bbbe01eeed093cb22bb8f5acdc3"
        assert hashes.sha1 == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        assert hashes.sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_binary_data(self):
        """Test hashing binary data."""
        data = bytes(range(256))
        hashes = compute_hashes_bytes(data)
        assert hashes.md5 == "e2c865db4162bed963bfaa9ef6ac18f0"
        assert hashes.sha1 == "4916d6bdb7f78e6803698cab32d1586ea457dfc8"
        assert hashes.sha256 == "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"


class TestComputeHashesStreaming:
    """Tests for compute_hashes_streaming function."""

    def test_streaming_empty(self):
        """Test streaming hash of empty file."""
        file_obj = io.BytesIO(b"")
        hashes = compute_hashes_streaming(file_obj)
        assert hashes.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert hashes.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert hashes.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_streaming_known_string(self):
        """Test streaming hash matches bytes hash."""
        data = b"hello world"
        file_obj = io.BytesIO(data)
        hashes = compute_hashes_streaming(file_obj)
        assert hashes.md5 == "5eb63bbbe01eeed093cb22bb8f5acdc3"
        assert hashes.sha1 == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        assert hashes.sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_streaming_large_file(self):
        """Test streaming hash of larger data."""
        # Create 1MB of data
        data = b"x" * (1024 * 1024)
        file_obj = io.BytesIO(data)
        hashes = compute_hashes_streaming(file_obj, chunk_size=8192)

        # Verify against bytes computation
        expected = compute_hashes_bytes(data)
        assert hashes.md5 == expected.md5
        assert hashes.sha1 == expected.sha1
        assert hashes.sha256 == expected.sha256

    def test_streaming_custom_chunk_size(self):
        """Test streaming with various chunk sizes."""
        data = b"test data for streaming hash computation"

        # Test with different chunk sizes
        for chunk_size in [1, 2, 4, 8, 16, 32, 64]:
            file_obj = io.BytesIO(data)
            hashes = compute_hashes_streaming(file_obj, chunk_size=chunk_size)
            expected = compute_hashes_bytes(data)
            assert hashes.sha256 == expected.sha256, f"Failed for chunk size {chunk_size}"


class TestValidateSha256:
    """Tests for validate_sha256 function."""

    def test_valid_hash(self):
        """Test validation with correct hash."""
        data = b"hello world"
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert validate_sha256(data, expected) is True

    def test_invalid_hash(self):
        """Test validation with incorrect hash."""
        data = b"hello world"
        wrong_hash = "a" * 64
        assert validate_sha256(data, wrong_hash) is False

    def test_case_insensitive(self):
        """Test validation is case insensitive."""
        data = b"hello world"
        upper_hash = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
        lower_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert validate_sha256(data, upper_hash) is True
        assert validate_sha256(data, lower_hash) is True
