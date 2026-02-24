"""Web Console entrypoint."""

from scarabeo.banner import show_banner
from services.web.config import config


def main() -> None:
    """Start the Web Console."""
    show_banner()

    import uvicorn
    uvicorn.run(
        "services.web.app:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
    )


if __name__ == "__main__":
    main()
