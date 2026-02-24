"""Scarabeo Analysis Framework - Startup Banner."""

_BANNER = """
              /\\                     /\\
             /  \\       ___       /  \\
            / /\\ \\     /___\\     / /\\ \\
           / /  \\ \\   ( 0 0 )   / /  \\ \\
          / /    \\ \\   \\ - /   / /    \\ \\
         / /      \\ \\__/ | \\__/ /      \\ \\
        /_/        \\_____|_____/        \\_\\
         \\ \\      /  \\  | |  /  \\      / /
          \\ \\    /    \\ | | /    \\    / /
           \\ \\  /     /_|_|_\\     \\  / /
            \\ \\/     /  |_|  \\     \\/ /
             \\______/   |_|   \\______/
                /  \\     |     /  \\
               /____\\    |    /____\\
                  ||     |      ||
                  ||     |      ||

   ███████╗ ██████╗ █████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗
   ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔═══██╗
   ███████╗██║     ███████║██████╔╝███████║██████╔╝█████╗  ██║   ██║
   ╚════██║██║     ██╔══██║██╔══██╗██╔══██║██╔══██╗██╔══╝  ██║   ██║
   ███████║╚██████╗██║  ██║██║  ██║██║  ██║██████╔╝███████╗╚██████╔╝
   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝

            [ SCARABEO :: Analysis Framework ]
            [ Status :: Initialized ]
            [ Mode   :: Operational ]
            [ Version :: {version} ]
"""

_shown = False


def show_banner() -> None:
    """Print the Scarabeo banner once per process."""
    global _shown
    if not _shown:
        # Import version here to avoid circular dependency
        from scarabeo.version import get_version

        version = get_version()
        print(_BANNER.format(version=version))
        _shown = True


def get_banner_text() -> str:
    """Get the banner text with version."""
    from scarabeo.version import get_version

    version = get_version()
    return _BANNER.format(version=version)
