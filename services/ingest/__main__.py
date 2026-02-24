"""Ingest Service - Sample ingestion and job queuing."""

from services.ingest.config import settings
from services.ingest.app import create_app

app = create_app()


def main() -> None:
    """Start the Ingest service."""
    import uvicorn

    uvicorn.run(
        "services.ingest:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    main()
