"""Utility modules for the security analyzer."""

from .severity import SeverityCalculator, SeverityLevel, CVSSVector, SEVERITY_PRESETS
from .file_utils import FileUtils
from .model_formats import ModelFormatDetector, ModelFormat
from .fickling_utils import (
    is_fickling_available,
    is_fickling_pytorch_available,
    activate_safe_ml_environment,
    deactivate_safe_ml_environment,
    check_pickle_safety,
    analyze_pickle_file,
    analyze_pytorch_file,
    safe_load_pickle,
    trace_pickle_execution,
)

__all__ = [
    "SeverityCalculator",
    "SeverityLevel",
    "CVSSVector",
    "SEVERITY_PRESETS",
    "FileUtils",
    "ModelFormatDetector",
    "ModelFormat",
    # Fickling utilities
    "is_fickling_available",
    "is_fickling_pytorch_available",
    "activate_safe_ml_environment",
    "deactivate_safe_ml_environment",
    "check_pickle_safety",
    "analyze_pickle_file",
    "analyze_pytorch_file",
    "safe_load_pickle",
    "trace_pickle_execution",
]
