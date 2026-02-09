"""Security scanners for various ML model vulnerabilities."""

from .base_scanner import BaseScanner, Vulnerability, ScanResult, Severity, SeverityLevel
from .pickle_scanner import PickleScanner
from .graph_injection_scanner import GraphInjectionScanner
from .metadata_scanner import MetadataScanner
from .lambda_layer_scanner import LambdaLayerScanner
from .dependency_scanner import DependencyScanner
from .gguf_scanner import GGUFScanner
from .polyglot_scanner import PolyglotScanner
from .backdoor_scanner import BackdoorScanner
from .zip_slip_scanner import ZipSlipScanner
from .external_ref_scanner import ExternalRefScanner
from .secrets_scanner import SecretsScanner
from .modelscan_scanner import ModelScanScanner, is_modelscan_available, get_modelscan_version
from .guarddog_scanner import GuardDogScanner, is_guarddog_available, get_guarddog_version

__all__ = [
    "BaseScanner",
    "Vulnerability",
    "ScanResult",
    "Severity",
    "SeverityLevel",
    "PickleScanner",
    "GraphInjectionScanner",
    "MetadataScanner",
    "LambdaLayerScanner",
    "DependencyScanner",
    "GGUFScanner",
    "PolyglotScanner",
    "BackdoorScanner",
    "ZipSlipScanner",
    "ExternalRefScanner",
    "SecretsScanner",
    "ModelScanScanner",
    "is_modelscan_available",
    "get_modelscan_version",
    "GuardDogScanner",
    "is_guarddog_available",
    "get_guarddog_version",
]

# Registry of all available scanners (13 scanners)
SCANNER_REGISTRY = {
    "pickle": PickleScanner,
    "graph_injection": GraphInjectionScanner,
    "metadata": MetadataScanner,
    "lambda_layer": LambdaLayerScanner,
    "dependency": DependencyScanner,
    "gguf": GGUFScanner,
    "polyglot": PolyglotScanner,
    "backdoor": BackdoorScanner,
    "zip_slip": ZipSlipScanner,
    "external_ref": ExternalRefScanner,
    "secrets": SecretsScanner,
    "modelscan": ModelScanScanner,
    "guarddog": GuardDogScanner,
}
