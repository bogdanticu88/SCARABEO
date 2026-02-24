"""S3 storage client for sample storage."""

import io
from functools import lru_cache
from typing import BinaryIO

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from services.ingest.config import settings


class S3StorageError(Exception):
    """S3 storage operation error."""

    pass


class S3StorageClient:
    """Client for S3-compatible storage (MinIO)."""

    def __init__(
        self,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        bucket: str | None = None,
        region: str | None = None,
    ):
        """
        Initialize S3 client.

        Args:
            endpoint_url: S3 endpoint URL
            access_key: Access key ID
            secret_key: Secret access key
            bucket: Default bucket name
            region: AWS region
        """
        self.endpoint_url = endpoint_url or settings.S3_ENDPOINT_URL
        self.access_key = access_key or settings.S3_ACCESS_KEY
        self.secret_key = secret_key or settings.S3_SECRET_KEY
        self.bucket = bucket or settings.S3_BUCKET
        self.region = region or settings.S3_REGION

        self._client = self._create_client()

    def _create_client(self):
        """Create boto3 S3 client."""
        return boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            config=Config(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    def ensure_bucket_exists(self, bucket: str | None = None) -> None:
        """
        Ensure bucket exists, create if not.

        Args:
            bucket: Bucket name (uses default if not provided)
        """
        bucket_name = bucket or self.bucket
        try:
            self._client.head_bucket(Bucket=bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                self._client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )
            else:
                raise S3StorageError(f"Failed to check bucket: {e}") from e

    def upload_file(
        self,
        file_obj: BinaryIO,
        object_key: str,
        bucket: str | None = None,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """
        Upload file to S3.

        Args:
            file_obj: File object opened in binary mode
            object_key: S3 object key (path)
            bucket: Bucket name (uses default if not provided)
            content_type: MIME type of the file
            metadata: Additional metadata

        Returns:
            S3 ETag of uploaded object

        Raises:
            S3StorageError: If upload fails
        """
        bucket_name = bucket or self.bucket

        try:
            # Prepare upload arguments
            upload_args = {
                "Bucket": bucket_name,
                "Key": object_key,
                "Body": file_obj,
            }

            if content_type:
                upload_args["ContentType"] = content_type

            if metadata:
                upload_args["Metadata"] = metadata

            response = self._client.put_object(**upload_args)
            return response.get("ETag", "").strip('"')

        except ClientError as e:
            raise S3StorageError(f"Failed to upload {object_key}: {e}") from e

    def upload_bytes(
        self,
        data: bytes,
        object_key: str,
        bucket: str | None = None,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """
        Upload bytes to S3.

        Args:
            data: File content as bytes
            object_key: S3 object key (path)
            bucket: Bucket name (uses default if not provided)
            content_type: MIME type of the file
            metadata: Additional metadata

        Returns:
            S3 ETag of uploaded object
        """
        file_obj = io.BytesIO(data)
        return self.upload_file(
            file_obj=file_obj,
            object_key=object_key,
            bucket=bucket,
            content_type=content_type,
            metadata=metadata,
        )

    def download_file(
        self,
        object_key: str,
        bucket: str | None = None,
    ) -> bytes:
        """
        Download file from S3.

        Args:
            object_key: S3 object key (path)
            bucket: Bucket name (uses default if not provided)

        Returns:
            File content as bytes

        Raises:
            S3StorageError: If download fails or object not found
        """
        bucket_name = bucket or self.bucket

        try:
            response = self._client.get_object(Bucket=bucket_name, Key=object_key)
            return response["Body"].read()

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise S3StorageError(f"Object not found: {object_key}") from e
            raise S3StorageError(f"Failed to download {object_key}: {e}") from e

    def delete_file(
        self,
        object_key: str,
        bucket: str | None = None,
    ) -> None:
        """
        Delete file from S3.

        Args:
            object_key: S3 object key (path)
            bucket: Bucket name (uses default if not provided)

        Raises:
            S3StorageError: If deletion fails
        """
        bucket_name = bucket or self.bucket

        try:
            self._client.delete_object(Bucket=bucket_name, Key=object_key)
        except ClientError as e:
            raise S3StorageError(f"Failed to delete {object_key}: {e}") from e

    def file_exists(
        self,
        object_key: str,
        bucket: str | None = None,
    ) -> bool:
        """
        Check if file exists in S3.

        Args:
            object_key: S3 object key (path)
            bucket: Bucket name (uses default if not provided)

        Returns:
            True if file exists, False otherwise
        """
        bucket_name = bucket or self.bucket

        try:
            self._client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise S3StorageError(f"Failed to check {object_key}: {e}") from e

    def get_storage_path(self, tenant_id: str, sha256: str) -> str:
        """
        Generate standard storage path for a sample.

        Args:
            tenant_id: Tenant identifier
            sha256: Sample SHA256 hash

        Returns:
            S3 object key path
        """
        return f"samples/{tenant_id}/{sha256}/original.bin"


@lru_cache
def get_storage_client() -> S3StorageClient:
    """Get cached S3 storage client."""
    return S3StorageClient()
