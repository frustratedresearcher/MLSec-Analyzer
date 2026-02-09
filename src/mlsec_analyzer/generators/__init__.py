"""Test case generators for creating malicious model files.

This module provides generators that create crafted malicious files
containing exploit payloads targeting various parser vulnerabilities.

These test cases are for:
- Security research and vulnerability testing
- Testing the scanner's detection capabilities
- Educational purposes

WARNING: Generated files contain real exploit payloads that can crash
or compromise vulnerable parsers. Use only in isolated environments.
"""

from .base_generator import BaseTestCaseGenerator
from .gguf_generator import GGUFTestCaseGenerator
from .pickle_generator import PickleTestCaseGenerator
from .keras_generator import KerasTestCaseGenerator
from .numpy_generator import NumpyTestCaseGenerator
from .tensorflow_generator import TensorFlowTestCaseGenerator

# Registry of all generators
GENERATORS = {
    "gguf": GGUFTestCaseGenerator,
    "pickle": PickleTestCaseGenerator,
    "keras": KerasTestCaseGenerator,
    "numpy": NumpyTestCaseGenerator,
    "tensorflow": TensorFlowTestCaseGenerator,
}

# Format aliases
FORMAT_ALIASES = {
    "pkl": "pickle",
    "pth": "pickle",
    "pt": "pickle",
    "h5": "keras",
    "hdf5": "keras",
    "npz": "numpy",
    "npy": "numpy",
    "pb": "tensorflow",
    "savedmodel": "tensorflow",
}

def get_generator(format_name: str) -> BaseTestCaseGenerator:
    """Get a test case generator for the specified format."""
    # Resolve aliases
    format_key = FORMAT_ALIASES.get(format_name.lower(), format_name.lower())
    
    if format_key not in GENERATORS:
        available = list(GENERATORS.keys()) + list(FORMAT_ALIASES.keys())
        raise ValueError(f"Unknown format: {format_name}. Available: {', '.join(sorted(set(available)))}")
    
    return GENERATORS[format_key]()

def list_formats() -> list:
    """List all supported formats."""
    return list(GENERATORS.keys())

__all__ = [
    "BaseTestCaseGenerator",
    "GGUFTestCaseGenerator", 
    "PickleTestCaseGenerator",
    "KerasTestCaseGenerator",
    "NumpyTestCaseGenerator",
    "TensorFlowTestCaseGenerator",
    "GENERATORS",
    "FORMAT_ALIASES",
    "get_generator",
    "list_formats",
]
