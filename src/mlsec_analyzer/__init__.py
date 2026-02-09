"""ML Model Security Analyzer - Static security analysis for ML model files.

A comprehensive security analyzer for machine learning model files that detects:
- Pickle deserialization attacks
- Lambda layer code execution (CVE-2024-3660)
- Computational graph injection
- GGUF format exploits
- Dependency hijacking
- Neural backdoors
- And many more...

Usage as Library:
    >>> import mlsec_analyzer
    >>> analyzer = mlsec_analyzer.Analyzer({})
    >>> result = analyzer.analyze("model.pkl")
    >>> print(result.summary)

    # Or use individual scanners
    >>> from mlsec_analyzer.scanners import PickleScanner
    >>> scanner = PickleScanner()
    >>> result = scanner.scan("model.pkl", {})
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .analyzer import Analyzer, AnalysisResult
from .extractor import ModelExtractor
from .utils import ModelFormatDetector

# Convenience imports for common use cases
from .scanners import (
    SCANNER_REGISTRY,
    BaseScanner,
    ScanResult,
    Vulnerability,
    Severity,
    SeverityLevel,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    # Main classes
    "Analyzer",
    "AnalysisResult",
    "ModelExtractor",
    "ModelFormatDetector",
    # Scanner framework
    "SCANNER_REGISTRY",
    "BaseScanner",
    "ScanResult",
    "Vulnerability",
    "Severity",
    "SeverityLevel",
]


def scan(path: str, **kwargs) -> AnalysisResult:
    """Convenience function to scan a model file or directory.
    
    Args:
        path: Path to model file or directory
        **kwargs: Additional options:
            - include_scanners: List of scanner names to include
            - exclude_scanners: List of scanner names to exclude
            - config: Custom configuration dict
    
    Returns:
        AnalysisResult with vulnerabilities found
    
    Example:
        >>> import mlsec_analyzer
        >>> result = mlsec_analyzer.scan("model.pkl")
        >>> print(f"Found {result.summary['total_vulnerabilities']} vulnerabilities")
    """
    config = kwargs.pop("config", {})
    include = kwargs.pop("include_scanners", None)
    exclude = kwargs.pop("exclude_scanners", None)
    
    analyzer = Analyzer(config)
    return analyzer.scan_path(path, include_scanners=include, exclude_scanners=exclude)


def get_available_scanners() -> dict:
    """Get all available scanners.
    
    Returns:
        Dictionary of scanner_name -> scanner_class
    
    Example:
        >>> import mlsec_analyzer
        >>> scanners = mlsec_analyzer.get_available_scanners()
        >>> print(list(scanners.keys()))
        ['pickle', 'graph_injection', 'metadata', ...]
    """
    return SCANNER_REGISTRY.copy()
