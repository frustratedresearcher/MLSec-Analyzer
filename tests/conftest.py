"""Pytest configuration and shared fixtures."""

import os
import sys
import tempfile

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def temp_directory():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def sample_config():
    """Provide sample configuration for tests."""
    return {
        "scanners": {
            "pickle_scanner": {"enabled": True},
            "zip_slip_scanner": {"enabled": True},
        },
        "severity": {
            "threshold": "low",
            "fail_on_critical": True,
        },
        "extraction": {
            "max_file_size_mb": 100,
            "timeout_seconds": 60,
        },
    }
