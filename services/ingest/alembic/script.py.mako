"""Alembic script template."""

from alembic import context
from alembic.operations import ops
from alembic.script import ScriptDirectory
from alembic.script.revision import ResolutionError
from alembic.util import CommandError
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alembic.runtime.environment import EnvironmentContext

def process_revision_directives(
    context: "EnvironmentContext",
    revision: str | tuple[str, ...],
    directives: list[ops.MigrationDirective],
) -> None:
    """Process revision directives."""
    script: ScriptDirectory = context.script  # type: ignore
    try:
        script.get_revision(revision)  # type: ignore
    except (ResolutionError, CommandError):
        pass
