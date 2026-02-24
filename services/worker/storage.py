"""S3 storage client for worker."""

import io
import json
from functools import lru_cache
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from services.worker.config import settings


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
        """Ensure bucket exists."""
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

    def upload_json(
        self,
        data: dict,
        object_key: str,
        bucket: str | None = None,
    ) -> str:
        """
        Upload JSON data to S3.

        Args:
            data: Dictionary to serialize and upload
            object_key: S3 object key
            bucket: Bucket name

        Returns:
            ETag of uploaded object
        """
        json_bytes = json.dumps(data, indent=2).encode("utf-8")
        return self.upload_bytes(
            data=json_bytes,
            object_key=object_key,
            bucket=bucket,
            content_type="application/json",
        )

    def upload_bytes(
        self,
        data: bytes,
        object_key: str,
        bucket: str | None = None,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Upload bytes to S3."""
        bucket_name = bucket or self.bucket
        file_obj = io.BytesIO(data)

        upload_args = {
            "Bucket": bucket_name,
            "Key": object_key,
            "Body": file_obj,
        }

        if content_type:
            upload_args["ContentType"] = content_type
        if metadata:
            upload_args["Metadata"] = metadata

        try:
            response = self._client.put_object(**upload_args)
            return response.get("ETag", "").strip('"')
        except ClientError as e:
            raise S3StorageError(f"Failed to upload {object_key}: {e}") from e

    def upload_file(
        self,
        file_path: Path,
        object_key: str,
        bucket: str | None = None,
        content_type: str | None = None,
    ) -> str:
        """Upload file to S3."""
        bucket_name = bucket or self.bucket

        try:
            with open(file_path, "rb") as f:
                upload_args = {
                    "Bucket": bucket_name,
                    "Key": object_key,
                    "Body": f,
                }
                if content_type:
                    upload_args["ContentType"] = content_type
                response = self._client.put_object(**upload_args)
                return response.get("ETag", "").strip('"')
        except Exception as e:
            raise S3StorageError(f"Failed to upload {file_path}: {e}") from e

    def download_file(
        self,
        object_key: str,
        file_path: Path,
        bucket: str | None = None,
    ) -> None:
        """Download file from S3."""
        bucket_name = bucket or self.bucket
        try:
            self._client.download_file(bucket_name, object_key, str(file_path))
        except ClientError as e:
            raise S3StorageError(f"Failed to download {object_key}: {e}") from e

    def download_json(
        self,
        object_key: str,
        bucket: str | None = None,
    ) -> dict:
        """Download JSON from S3."""
        bucket_name = bucket or self.bucket

        try:
            response = self._client.get_object(Bucket=bucket_name, Key=object_key)
            return json.loads(response["Body"].read().decode("utf-8"))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise S3StorageError(f"Object not found: {object_key}") from e
            raise S3StorageError(f"Failed to download {object_key}: {e}") from e

    def file_exists(self, object_key: str, bucket: str | None = None) -> bool:
        """Check if file exists in S3."""
        bucket_name = bucket or self.bucket

        try:
            self._client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise S3StorageError(f"Failed to check {object_key}: {e}") from e

    def get_report_path(
        self,
        tenant_id: str,
        sha256: str,
        pipeline_hash: str,
    ) -> str:
        """Generate report storage path."""
        return f"samples/{tenant_id}/{sha256}/reports/{pipeline_hash}/report.json"

    def get_artifact_path(
        self,
        tenant_id: str,
        sha256: str,
        pipeline_hash: str,
        filename: str,
    ) -> str:
        """Generate artifact storage path."""
        return f"samples/{tenant_id}/{sha256}/artifacts/{pipeline_hash}/{filename}"


@lru_cache
def get_storage_client() -> S3StorageClient:
    """Get cached S3 storage client."""
    return S3StorageClient()
