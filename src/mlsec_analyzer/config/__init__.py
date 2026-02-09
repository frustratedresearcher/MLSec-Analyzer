"""Configuration management for the security analyzer."""

from .default_config import DEFAULT_CONFIG, load_config, merge_configs

__all__ = [
    "DEFAULT_CONFIG",
    "load_config",
    "merge_configs",
]
