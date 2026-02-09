"""SARIF (Static Analysis Results Interchange Format) reporter."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from ..analyzer import AnalysisResult
from ..scanners.base_scanner import Vulnerability


class SARIFReporter:
    """Generates SARIF 2.1.0 reports for GitHub Advanced Security integration."""
    
    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the SARIF reporter.
        
        Args:
            config: Reporter configuration.
        """
        self.config = config or {}
    
    def generate(self, results: AnalysisResult) -> Dict[str, Any]:
        """Generate a SARIF report from analysis results.
        
        Args:
            results: Analysis results to report.
            
        Returns:
            SARIF-formatted dictionary.
        """
        sarif_report = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                self._create_run(results)
            ]
        }
        
        return sarif_report
    
    def _create_run(self, results: AnalysisResult) -> Dict[str, Any]:
        """Create a SARIF run object."""
        return {
            "tool": self._create_tool(),
            "results": self._create_results(results.vulnerabilities),
            "invocations": [
                {
                    "executionSuccessful": len(results.errors) == 0,
                    "endTimeUtc": results.scan_metadata.get(
                        "scan_timestamp",
                        datetime.utcnow().isoformat() + "Z"
                    ),
                    "toolExecutionNotifications": [
                        {
                            "level": "error",
                            "message": {"text": error}
                        }
                        for error in results.errors
                    ] if results.errors else []
                }
            ],
            "artifacts": [
                {
                    "location": {
                        "uri": results.scan_metadata.get("target", "unknown")
                    },
                    "roles": ["analysisTarget"]
                }
            ] if results.scan_metadata.get("target") else []
        }
    
    def _create_tool(self) -> Dict[str, Any]:
        """Create the SARIF tool object."""
        return {
            "driver": {
                "name": "ML Model Security Analyzer",
                "version": "1.0.0",
                "informationUri": "https://github.com/example/ml-model-security-analyzer",
                "rules": self._create_rules()
            }
        }
    
    def _create_rules(self) -> List[Dict[str, Any]]:
        """Create SARIF rule definitions for vulnerability types."""
        rules = [
            {
                "id": "MLSEC001",
                "name": "PickleDeserialization",
                "shortDescription": {"text": "Pickle Deserialization Vulnerability"},
                "fullDescription": {
                    "text": "The model file uses Python pickle serialization which can execute arbitrary code during deserialization."
                },
                "helpUri": "https://research.jfrog.com/model-threats/pickle-malcode/",
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "9.8"}
            },
            {
                "id": "MLSEC002",
                "name": "GraphInjection",
                "shortDescription": {"text": "TensorFlow Graph Injection"},
                "fullDescription": {
                    "text": "The TensorFlow model contains operations that can execute arbitrary code."
                },
                "helpUri": "https://github.com/tensorflow/tensorflow/security/policy",
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "9.1"}
            },
            {
                "id": "MLSEC003",
                "name": "MetadataExploitation",
                "shortDescription": {"text": "Metadata Header Exploitation"},
                "fullDescription": {
                    "text": "Model metadata contains patterns that could exploit buffer overflows or format string vulnerabilities."
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {"security-severity": "7.5"}
            },
            {
                "id": "MLSEC004",
                "name": "LambdaLayerExecution",
                "shortDescription": {"text": "Keras Lambda Layer Code Execution"},
                "fullDescription": {
                    "text": "Keras model contains Lambda layers that execute arbitrary Python code when loaded."
                },
                "helpUri": "https://research.jfrog.com/model-threats/keras-lambda/",
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "9.0"}
            },
            {
                "id": "MLSEC005",
                "name": "DependencyHijacking",
                "shortDescription": {"text": "Dependency Hijacking / Typosquatting"},
                "fullDescription": {
                    "text": "Model package references suspicious dependencies that may be typosquatting attacks."
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {"security-severity": "8.1"}
            },
            {
                "id": "MLSEC006",
                "name": "GGUFExploit",
                "shortDescription": {"text": "GGUF Format Vulnerability"},
                "fullDescription": {
                    "text": "GGUF file contains patterns that could exploit buffer overflow or integer overflow vulnerabilities."
                },
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "8.8"}
            },
            {
                "id": "MLSEC007",
                "name": "PolyglotFile",
                "shortDescription": {"text": "Polyglot File Attack"},
                "fullDescription": {
                    "text": "File is valid in multiple formats, potentially used to bypass security filters."
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {"security-severity": "6.5"}
            },
            {
                "id": "MLSEC008",
                "name": "NeuralBackdoor",
                "shortDescription": {"text": "Neural Backdoor / Trojan"},
                "fullDescription": {
                    "text": "Model weights show anomalous patterns that may indicate a backdoor or trojan."
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {"security-severity": "7.0"}
            },
            {
                "id": "MLSEC009",
                "name": "ZipSlip",
                "shortDescription": {"text": "Zip Slip Path Traversal"},
                "fullDescription": {
                    "text": "Archive contains entries with path traversal that could overwrite arbitrary files."
                },
                "helpUri": "https://research.jfrog.com/model-threats/zipslip/",
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "7.5"}
            },
            {
                "id": "MLSEC010",
                "name": "ExternalReference",
                "shortDescription": {"text": "External Reference Injection / SSRF"},
                "fullDescription": {
                    "text": "Model contains external URLs that could enable SSRF attacks or malicious payload downloads."
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {"security-severity": "7.2"}
            },
        ]
        
        return rules
    
    def _create_results(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """Create SARIF results from vulnerabilities."""
        results = []
        
        for vuln in vulnerabilities:
            result = {
                "ruleId": self._get_rule_id(vuln),
                "level": self._severity_to_level(vuln.severity.level if hasattr(vuln.severity, "level") else str(vuln.severity)),
                "message": {
                    "text": vuln.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": self._normalize_path(vuln.location.get("file", "unknown"))
                            }
                        }
                    }
                ],
                "properties": {
                    "vulnerability_id": vuln.id,
                    "vulnerability_type": vuln.vulnerability_type,
                    "cvss_score": vuln.severity.cvss_score if hasattr(vuln.severity, "cvss_score") else None,
                    "cvss_vector": vuln.severity.cvss_vector if hasattr(vuln.severity, "cvss_vector") else None,
                    "cwe_id": vuln.cwe_id,
                    "cve_id": vuln.cve_id,
                }
            }
            
            # Add fix suggestion if available
            if vuln.recommendation:
                result["fixes"] = [
                    {
                        "description": {
                            "text": vuln.recommendation
                        }
                    }
                ]
            
            # Add related locations for evidence
            if vuln.evidence:
                result["relatedLocations"] = []
                for key, value in list(vuln.evidence.items())[:5]:
                    result["relatedLocations"].append({
                        "message": {"text": f"{key}: {str(value)[:200]}"}
                    })
            
            results.append(result)
        
        return results
    
    def _get_rule_id(self, vuln: Vulnerability) -> str:
        """Map vulnerability type to rule ID."""
        vuln_type = vuln.vulnerability_type.lower()
        
        mapping = {
            "pickle": "MLSEC001",
            "graph": "MLSEC002",
            "metadata": "MLSEC003",
            "lambda": "MLSEC004",
            "dependency": "MLSEC005",
            "gguf": "MLSEC006",
            "polyglot": "MLSEC007",
            "backdoor": "MLSEC008",
            "zip": "MLSEC009",
            "slip": "MLSEC009",
            "external": "MLSEC010",
            "ssrf": "MLSEC010",
        }
        
        for keyword, rule_id in mapping.items():
            if keyword in vuln_type:
                return rule_id
        
        return "MLSEC000"  # Unknown
    
    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        severity_lower = severity.lower()
        
        if severity_lower == "critical":
            return "error"
        elif severity_lower == "high":
            return "error"
        elif severity_lower == "medium":
            return "warning"
        elif severity_lower == "low":
            return "note"
        else:
            return "none"
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path for SARIF URI format."""
        # Convert Windows paths to URI format
        path = path.replace("\\", "/")
        
        # Handle absolute paths
        if path.startswith("/"):
            return f"file://{path}"
        elif len(path) > 1 and path[1] == ":":
            # Windows drive letter
            return f"file:///{path}"
        
        return path
    
    def to_string(self, results: AnalysisResult, indent: int = 2) -> str:
        """Generate SARIF JSON string.
        
        Args:
            results: Analysis results.
            indent: JSON indentation.
            
        Returns:
            SARIF JSON string.
        """
        report = self.generate(results)
        return json.dumps(report, indent=indent, default=str)
    
    def save(self, results: AnalysisResult, output_path: str, indent: int = 2):
        """Save SARIF report to file.
        
        Args:
            results: Analysis results.
            output_path: Output file path.
            indent: JSON indentation.
        """
        report = self.generate(results)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=indent, default=str)
