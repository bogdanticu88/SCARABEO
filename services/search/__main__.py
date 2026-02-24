"""Search service entrypoint."""

from scarabeo.banner import show_banner
from services.search.config import config


def main() -> None:
    """Start the Search service."""
    show_banner()

    import uvicorn
    uvicorn.run(
        "services.search.app:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
    )


if __name__ == "__main__":
    main()
