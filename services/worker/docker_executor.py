"""Docker container execution for analyzers."""

import logging
import tempfile
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, NotFound
from docker.types import Mount

from services.worker.config import settings

logger = logging.getLogger(__name__)


class DockerExecutionError(Exception):
    """Docker execution error."""

    pass


class DockerExecutor:
    """Execute analyzers in isolated Docker containers."""

    def __init__(self):
        """Initialize Docker client."""
        try:
            self.client = docker.from_env()
            # Test connection
            self.client.ping()
        except DockerException as e:
            logger.error(f"Failed to connect to Docker: {e}")
            raise DockerExecutionError(f"Cannot connect to Docker: {e}") from e

    def run_analyzer(
        self,
        image: str,
        work_dir: Path,
        sample_path: Path,
        input_data: dict[str, Any],
        timeout: int | None = None,
    ) -> tuple[dict, dict]:
        """
        Run analyzer container with isolated execution.

        Args:
            image: Docker image name
            work_dir: Working directory for container mounts
            sample_path: Path to the sample file on host
            input_data: Input data to write to input.json
            timeout: Container execution timeout in seconds

        Returns:
            Tuple of (report_data, container_info)

        Raises:
            DockerExecutionError: If container execution fails
        """
        # Ensure work directory structure
        work_dir.mkdir(parents=True, exist_ok=True)
        output_dir = work_dir / "output"
        output_dir.mkdir(exist_ok=True)

        # Write input.json
        import json

        input_path = work_dir / "input.json"
        with open(input_path, "w") as f:
            json.dump(input_data, f, indent=2)

        # Configure container with security hardening
        container_config = {
            "image": image,
            "detach": True,
            "remove": True,
            "network_disabled": settings.DOCKER_NETWORK_DISABLED,
            "read_only": settings.DOCKER_READONLY_ROOTFS,
            "tmpfs": {
                "/tmp": "rw,noexec,nosuid,size=64m",
            },
            "mounts": [
                Mount(
                    target="/work/input.json",
                    source=str(input_path),
                    type="bind",
                    read_only=True,
                ),
                Mount(
                    target="/work/sample",
                    source=str(sample_path),
                    type="bind",
                    read_only=True,
                ),
                Mount(
                    target="/work/output",
                    source=str(output_dir),
                    type="bind",
                    read_only=False,
                ),
            ],
            "nano_cpus": int(settings.DOCKER_CPU_LIMIT * 1e9),
            "mem_limit": settings.DOCKER_MEMORY_LIMIT,
            # Security hardening
            "cap_drop": ["ALL"],
            "security_opt": [
                "no-new-privileges:true",
                "seccomp:default",
            ],
            "pids_limit": 50,
            "ulimits": [
                docker.types.Ulimit(name="nofile", soft=1024, hard=1024),
                docker.types.Ulimit(name="nproc", soft=256, hard=256),
            ],
            "environment": {
                "ANALYZER_CHUNK_SIZE": str(settings.ANALYZER_CHUNK_SIZE),
                "ANALYZER_MAX_STRINGS": str(settings.ANALYZER_MAX_STRINGS),
                "ANALYZER_HIGH_ENTROPY_THRESHOLD": str(settings.ANALYZER_HIGH_ENTROPY_THRESHOLD),
            },
        }

        logger.info(f"Starting analyzer container: {image}")

        try:
            # Create and start container
            container = self.client.containers.run(**container_config)

            # Wait for completion with timeout
            result = container.wait(timeout=timeout or 300)

            # Get exit code
            exit_code = result.get("StatusCode", -1)

            # Get logs
            logs = container.logs().decode("utf-8", errors="replace")

            if exit_code != 0:
                logger.error(f"Container failed with exit code {exit_code}: {logs}")
                raise DockerExecutionError(
                    f"Analyzer failed with exit code {exit_code}: {logs[:500]}"
                )

            # Read output
            report_path = output_dir / "report.json"
            if not report_path.exists():
                raise DockerExecutionError(
                    "Analyzer did not produce report.json output"
                )

            with open(report_path, "r") as f:
                report_data = json.load(f)

            # Collect artifacts info
            artifacts_info = {}
            for artifact_file in (output_dir / "artifacts").glob("*"):
                if artifact_file.is_file():
                    artifacts_info[artifact_file.name] = {
                        "path": str(artifact_file),
                        "size": artifact_file.stat().st_size,
                    }

            container_info = {
                "exit_code": exit_code,
                "logs": logs[-1000:],  # Last 1000 chars
                "artifacts": artifacts_info,
            }

            logger.info(f"Analyzer completed successfully: {image}")
            return report_data, container_info

        except Exception as e:
            logger.exception(f"Container execution failed: {e}")
            raise DockerExecutionError(f"Container execution failed: {e}") from e

    def pull_image(self, image: str) -> bool:
        """
        Pull Docker image if not present.

        Args:
            image: Image name to pull

        Returns:
            True if successful
        """
        try:
            logger.info(f"Pulling image: {image}")
            self.client.images.pull(image)
            return True
        except NotFound:
            logger.error(f"Image not found: {image}")
            return False
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False

    def image_exists(self, image: str) -> bool:
        """Check if image exists locally."""
        try:
            self.client.images.get(image)
            return True
        except NotFound:
            return False
        except Exception as e:
            logger.warning(f"Error checking image {image}: {e}")
            return False


def get_docker_executor() -> DockerExecutor:
    """Get Docker executor instance."""
    return DockerExecutor()
