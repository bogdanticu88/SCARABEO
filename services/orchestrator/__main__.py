"""Orchestrator Service - Job orchestration and worker dispatch."""

from services.orchestrator.config import settings
from services.orchestrator.app import create_app

app = create_app()


def main() -> None:
    """Start the Orchestrator service."""
    import uvicorn

    uvicorn.run(
        "services.orchestrator:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    main()
