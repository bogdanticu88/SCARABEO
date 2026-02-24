"""Worker Service - Analyzer execution in isolated containers."""

from services.worker.config import settings
from services.worker.worker import run_worker

import sys


def main() -> None:
    """Start the Worker service."""
    from scarabeo.banner import show_banner

    show_banner()

    # Run worker loop
    run_worker()


if __name__ == "__main__":
    main()
