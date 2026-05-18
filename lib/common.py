import os
from typing import Any


def load_config(config_path: str) -> dict[str, Any]:
    """Load YAML config. Returns empty dict if config missing or invalid."""
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def apply_thread_override(config: dict, threads: int | None) -> dict[str, Any]:
    """Override thread count in config if --threads was passed via CLI."""
    if threads is not None and threads > 0:
        if "target" not in config:
            config["target"] = {}
        config["target"]["threads"] = threads
    return config
