"""Runtime JSON schema validation for the worker pipeline."""

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

_SCHEMAS_DIR = Path(__file__).parent.parent / "contracts" / "schemas"


class SchemaValidationError(ValueError):
    """Raised when a partial or report fails schema validation."""


@lru_cache(maxsize=None)
def _load_schema(name: str) -> dict:
    schema_path = _SCHEMAS_DIR / f"{name}.schema.json"
    with open(schema_path, "r") as f:
        return json.load(f)


def _format_error(schema_name: str, context_label: str, error: ValidationError) -> str:
    # Walk to the deepest (most specific) cause
    cause = error
    while cause.context:
        cause = min(cause.context, key=lambda e: len(list(e.absolute_path)))

    path_parts = list(cause.absolute_path)
    path_str = " -> ".join(str(p) for p in path_parts) if path_parts else "<root>"
    return (
        f"Schema validation failed for '{schema_name}' ({context_label}):\n"
        f"  {cause.message}\n"
        f"  [path: {path_str}]"
    )


def validate_partial(data: dict, analyzer_name: str) -> None:
    """
    Validate a partial analyzer output against partial.schema.json.

    Raises:
        SchemaValidationError: If the data does not conform to the schema.
    """
    schema = _load_schema("partial")
    validator = Draft202012Validator(schema)
    error = next(iter(validator.iter_errors(data)), None)
    if error is not None:
        msg = _format_error("partial", f"analyzer: '{analyzer_name}'", error)
        raise SchemaValidationError(msg)


def validate_report(data: dict) -> None:
    """
    Validate a merged report against report.schema.json.

    Raises:
        SchemaValidationError: If the data does not conform to the schema.
    """
    schema = _load_schema("report")
    validator = Draft202012Validator(schema)
    error = next(iter(validator.iter_errors(data)), None)
    if error is not None:
        sha256 = str(data.get("sample_sha256", "unknown"))[:16]
        msg = _format_error("report", f"sample: '{sha256}'", error)
        raise SchemaValidationError(msg)
