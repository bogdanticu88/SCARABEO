"""Analyzer router - selects analyzers based on file type and pipeline."""

from typing import Any


# Analyzer configuration
ANALYZERS = {
    "triage-universal": {
        "container": "scarabeo/triage-universal:latest",
        "version": "0.1.0",
        "always_run": True,
        "condition": None,
    },
    "pe-analyzer": {
        "container": "scarabeo/pe-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: ft == "pe",
    },
    "elf-analyzer": {
        "container": "scarabeo/elf-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: ft == "elf",
    },
    "script-analyzer": {
        "container": "scarabeo/script-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: ft == "script",
    },
    "doc-analyzer": {
        "container": "scarabeo/doc-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: ft == "document",
    },
    "archive-analyzer": {
        "container": "scarabeo/archive-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: ft == "archive",
    },
    "similarity-analyzer": {
        "container": "scarabeo/similarity-analyzer:latest",
        "version": "0.1.0",
        "always_run": True,
        "condition": None,
    },
    "yara-analyzer": {
        "container": "scarabeo/yara-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: True,
        "optional": True,
        "feature_flag": "YARA_ENABLED",
    },
    "capa-analyzer": {
        "container": "scarabeo/capa-analyzer:latest",
        "version": "0.1.0",
        "always_run": False,
        "condition": lambda ft: True,
        "optional": True,
        "feature_flag": "CAPA_ENABLED",
    },
}


def _select_mandatory(file_type: str) -> list[dict]:
    """
    Return the mandatory (non-optional) analyzers for a given file type.

    Includes all always-run analyzers and any analyzer whose condition
    evaluates to True for the given file type.  Optional (feature-flagged)
    analyzers are never included.
    """
    selected = []
    for name, config in ANALYZERS.items():
        if config.get("optional"):
            continue
        should_run = False
        if config.get("always_run"):
            should_run = True
        elif config.get("condition"):
            try:
                should_run = config["condition"](file_type)
            except Exception:
                should_run = False
        if should_run:
            selected.append({"name": name, **config})
    return selected


def get_analyzers_for_file_type(
    file_type: str,
    pipeline_name: str,
    feature_flags: dict[str, bool] | None = None,
) -> list[dict]:
    """
    Get list of analyzers to run for a given file type and pipeline.

    Pipeline semantics
    ------------------
    triage  — mandatory analyzers only (always-run + file-type conditional).
              Optional / feature-flagged analyzers are excluded.
              Example: PE file → triage-universal, pe-analyzer, similarity-analyzer.

    deep    — all applicable analyzers, including optional ones when their
              feature flag is enabled.

    archive — triage-universal, archive-analyzer, and similarity-analyzer,
              regardless of detected file type (archive pipeline is triggered
              by the submission context, not the inner file type).

    Any other pipeline_name falls back to the same logic as triage.

    Args:
        file_type:     Detected file type (pe, elf, script, document, archive, unknown)
        pipeline_name: Pipeline name (triage, deep, archive)
        feature_flags: Optional dict of feature flag overrides

    Returns:
        List of analyzer configuration dicts to run, in registration order.
    """
    feature_flags = feature_flags or {}

    if pipeline_name == "triage":
        return _select_mandatory(file_type)

    elif pipeline_name == "deep":
        # Deep runs mandatory analyzers plus optional ones when their flag is on
        selected = []
        for name, config in ANALYZERS.items():
            should_run = False

            if config.get("always_run"):
                should_run = True
            elif config.get("condition"):
                try:
                    should_run = config["condition"](file_type)
                except Exception:
                    should_run = False

            # Gate optional analyzers behind their feature flag
            if should_run and config.get("optional"):
                flag = config.get("feature_flag")
                if flag and not feature_flags.get(flag, False):
                    should_run = False

            if should_run:
                selected.append({"name": name, **config})

        return selected

    elif pipeline_name == "archive":
        # Archive pipeline is triggered by submission context, not inner file type
        selected = []
        for name, config in ANALYZERS.items():
            if name in ("triage-universal", "archive-analyzer"):
                selected.append({"name": name, **config})
            elif config.get("always_run") and name == "similarity-analyzer":
                selected.append({"name": name, **config})
        return selected

    # Unknown pipeline names fall back to mandatory routing (same as triage)
    return _select_mandatory(file_type)


def get_analyzer_container(name: str) -> str | None:
    """Get container image name for analyzer."""
    if name in ANALYZERS:
        return ANALYZERS[name]["container"]
    return None


def get_analyzer_version(name: str) -> str:
    """Get version for analyzer."""
    if name in ANALYZERS:
        return ANALYZERS[name]["version"]
    return "unknown"
