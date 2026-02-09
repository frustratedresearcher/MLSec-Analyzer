"""Default configuration for ML Model Security Analyzer."""

import os
from typing import Any, Dict, Optional
import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    # General settings
    "version": "1.0.0",
    
    # Scanner configurations
    "scanners": {
        "pickle_scanner": {
            "enabled": True,
            "check_reduce": True,
            "check_global": True,
            "allowed_imports": [
                "collections",
                "datetime",
                "numpy",
                "torch._utils",
            ],
            "dangerous_imports": [
                "os",
                "subprocess",
                "sys",
                "builtins",
                "eval",
                "exec",
                "compile",
                "__import__",
                "importlib",
                "pickle",
                "marshal",
                "pty",
                "socket",
                "http",
                "urllib",
                "requests",
                "ctypes",
                "multiprocessing",
            ],
        },
        "graph_injection_scanner": {
            "enabled": True,
            "dangerous_ops": [
                "PyFunc",
                "PyFuncStateless",
                "EagerPyFunc",
                "ReadFile",
                "WriteFile",
                "MatchingFiles",
                "ShardedFilename",
                "TFRecordReader",
            ],
        },
        "metadata_scanner": {
            "enabled": True,
            "max_string_length": 10000,
            "check_format_strings": True,
            "check_embedded_scripts": True,
        },
        "lambda_layer_scanner": {
            "enabled": True,
            "decompile_bytecode": True,
            "dangerous_patterns": [
                "os.system",
                "subprocess",
                "eval(",
                "exec(",
                "__import__",
                "open(",
                "requests.",
                "urllib.",
                "socket.",
            ],
        },
        "dependency_scanner": {
            "enabled": True,
            "check_typosquatting": True,
            "check_custom_repos": True,
            "known_packages": [
                "numpy",
                "torch",
                "tensorflow",
                "keras",
                "scikit-learn",
                "pandas",
                "scipy",
                "transformers",
                "huggingface-hub",
            ],
        },
        "gguf_scanner": {
            "enabled": True,
            "check_integer_overflow": True,
            "check_buffer_bounds": True,
            "max_tensor_count": 10000,
            "max_string_length": 1000000,
        },
        "polyglot_scanner": {
            "enabled": True,
            "check_magic_bytes": True,
            "check_embedded_formats": True,
        },
        "backdoor_scanner": {
            "enabled": True,
            "weight_analysis_depth": "final_layer",
            "outlier_threshold": 3.0,
            "entropy_threshold": 0.5,
        },
        "zip_slip_scanner": {
            "enabled": True,
            "check_symlinks": True,
            "check_absolute_paths": True,
        },
        "external_ref_scanner": {
            "enabled": True,
            "allowed_domains": [],
            "check_ssrf_patterns": True,
        },
    },
    
    # Severity settings
    "severity": {
        "threshold": "low",
        "fail_on_critical": True,
        "cvss_mapping": {
            "critical": {"min": 9.0, "max": 10.0},
            "high": {"min": 7.0, "max": 8.9},
            "medium": {"min": 4.0, "max": 6.9},
            "low": {"min": 0.0, "max": 3.9},
        },
    },
    
    # Extraction settings
    "extraction": {
        "max_file_size_mb": 500,
        "timeout_seconds": 300,
        "temp_dir": None,
        "cleanup_on_exit": True,
    },
    
    # Output settings
    "output": {
        "format": "json",
        "include_evidence": True,
        "include_recommendations": True,
        "include_references": True,
    },
    
    # PoC generation settings
    "poc": {
        "enabled": False,
        "output_dir": "./pocs",
        "formats": ["python", "json"],
        "include_safety_warnings": True,
    },
    
    # Remote extraction settings
    "remote": {
        "huggingface": {
            "enabled": True,
            "token_env_var": "HF_TOKEN",
        },
        "s3": {
            "enabled": True,
            "access_key_env_var": "AWS_ACCESS_KEY_ID",
            "secret_key_env_var": "AWS_SECRET_ACCESS_KEY",
        },
        "gcs": {
            "enabled": True,
            "credentials_env_var": "GOOGLE_APPLICATION_CREDENTIALS",
        },
        "http": {
            "enabled": True,
            "timeout_seconds": 60,
            "max_retries": 3,
        },
    },
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from a YAML or JSON file.
    
    Args:
        config_path: Path to configuration file. If None, returns default config.
        
    Returns:
        Configuration dictionary.
    """
    if config_path is None:
        return DEFAULT_CONFIG.copy()
    
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as f:
        if config_path.endswith((".yml", ".yaml")):
            user_config = yaml.safe_load(f)
        else:
            import json
            user_config = json.load(f)
    
    return merge_configs(DEFAULT_CONFIG, user_config)


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge two configuration dictionaries.
    
    Args:
        base: Base configuration dictionary.
        override: Override configuration dictionary.
        
    Returns:
        Merged configuration dictionary.
    """
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result
