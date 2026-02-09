"""ModelScan integration scanner.

Integrates ProtectAI's ModelScan for enhanced pickle-based vulnerability detection.
https://github.com/protectai/modelscan

ModelScan provides:
- Pickle deserialization attack detection
- PyTorch model scanning
- NumPy array scanning
- Keras Lambda layer detection
- TensorFlow SavedModel scanning

Note: ModelScan currently requires Python 3.9-3.13. If using Python 3.14+,
the scanner will attempt to use the CLI fallback. Install ModelScan CLI
separately: pip install modelscan (in a Python 3.9-3.13 environment)
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability

logger = logging.getLogger(__name__)

# Check Python version compatibility
PYTHON_VERSION = sys.version_info[:2]
MODELSCAN_PYTHON_COMPATIBLE = PYTHON_VERSION >= (3, 9) and PYTHON_VERSION < (3, 14)

# Check if modelscan is available
MODELSCAN_AVAILABLE = False
MODELSCAN_CLI_AVAILABLE = False

if MODELSCAN_PYTHON_COMPATIBLE:
    try:
        from modelscan.modelscan import ModelScan
        from modelscan.issues import IssueSeverity
        MODELSCAN_AVAILABLE = True
    except ImportError:
        logger.debug("modelscan package not installed")
else:
    logger.debug(f"Python {PYTHON_VERSION[0]}.{PYTHON_VERSION[1]} not compatible with modelscan (requires 3.9-3.13)")

# Check for CLI availability (works regardless of Python version)
try:
    result = subprocess.run(
        ["modelscan", "--version"],
        capture_output=True,
        text=True,
        timeout=10
    )
    if result.returncode == 0:
        MODELSCAN_CLI_AVAILABLE = True
        logger.debug(f"ModelScan CLI available: {result.stdout.strip()}")
except (subprocess.SubprocessError, FileNotFoundError, OSError):
    pass


class ModelScanScanner(BaseScanner):
    """Scanner that integrates ProtectAI's ModelScan.
    
    This scanner provides comprehensive pickle-based vulnerability detection
    by leveraging ModelScan's mature scanning capabilities:
    
    - Pickle deserialization attacks (unsafe operators/globals)
    - PyTorch model security (pickle inside .pt/.pth/.bin)
    - NumPy array security (pickle inside .npy)
    - Keras Lambda layer detection (.h5, .keras)
    - TensorFlow SavedModel scanning (.pb)
    
    ModelScan uses an operator allowlist/blocklist approach with severity levels
    for known dangerous modules and functions.
    """
    
    # Severity mapping from ModelScan to our format
    SEVERITY_MAP = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.5,
        "LOW": 3.0,
    }
    
    def get_name(self) -> str:
        return "ModelScan Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [
            # Pickle formats
            ".pkl", ".pickle", ".joblib", ".dill", ".dat", ".data",
            # PyTorch formats
            ".pt", ".pth", ".bin", ".ckpt",
            # NumPy
            ".npy",
            # Keras/TensorFlow
            ".h5", ".hdf5", ".keras", ".pb",
        ]
    
    def get_description(self) -> str:
        return (
            "Integrates ProtectAI ModelScan for comprehensive pickle-based "
            "vulnerability detection including PyTorch, NumPy, and Keras models"
        )
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a model file using ModelScan."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        # Check if ModelScan is available
        if not MODELSCAN_AVAILABLE and not MODELSCAN_CLI_AVAILABLE:
            if not MODELSCAN_PYTHON_COMPATIBLE:
                warning_msg = (
                    f"ModelScan requires Python 3.9-3.13 (current: {PYTHON_VERSION[0]}.{PYTHON_VERSION[1]}). "
                    "Install ModelScan CLI in a compatible environment for full support."
                )
            else:
                warning_msg = "ModelScan not available. Install with: pip install modelscan"
            
            result.add_warning(warning_msg)
            result.metadata["modelscan_status"] = "unavailable"
            result.metadata["modelscan_warning"] = warning_msg
            return result
        
        # Add status to metadata
        if MODELSCAN_AVAILABLE:
            result.metadata["modelscan_status"] = "python_api"
        else:
            result.metadata["modelscan_status"] = "cli_fallback"
        
        # Try Python API first, fall back to CLI
        if MODELSCAN_AVAILABLE:
            return self._scan_with_python_api(model_path, result)
        else:
            return self._scan_with_cli(model_path, result)
    
    def _scan_with_python_api(
        self, model_path: str, result: ScanResult
    ) -> ScanResult:
        """Scan using ModelScan Python API."""
        try:
            from modelscan.modelscan import ModelScan
            from modelscan.issues import IssueSeverity
            
            scanner = ModelScan()
            scan_result = scanner.scan(model_path)
            
            # Process issues
            issues = scan_result.get("issues", [])
            for issue in issues:
                self._process_issue(issue, model_path, result)
            
            # Add scan metadata
            scanned_files = scan_result.get("scanned", {}).get("scanned_files", [])
            if scanned_files:
                result.metadata["modelscan_scanned_files"] = scanned_files
            
            # Process errors from ModelScan
            errors = scan_result.get("errors", [])
            for error in errors:
                if isinstance(error, dict):
                    result.add_warning(f"ModelScan: {error.get('message', str(error))}")
                else:
                    result.add_warning(f"ModelScan: {error}")
            
        except Exception as e:
            logger.error(f"ModelScan Python API error: {e}")
            result.add_error(f"ModelScan scan failed: {e}")
        
        return result
    
    def _scan_with_cli(self, model_path: str, result: ScanResult) -> ScanResult:
        """Scan using ModelScan CLI."""
        try:
            # Create a temporary file for JSON output
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False
            ) as tmp:
                tmp_path = tmp.name
            
            try:
                # Run modelscan CLI
                cmd = [
                    "modelscan",
                    "--path", model_path,
                    "--report", "json",
                    "--output", tmp_path,
                ]
                
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                # Read JSON output
                if os.path.exists(tmp_path):
                    with open(tmp_path, 'r') as f:
                        scan_result = json.load(f)
                    
                    # Process issues by severity
                    issues_by_severity = scan_result.get("issues_by_severity", {})
                    for severity, issues in issues_by_severity.items():
                        for issue in issues:
                            self._process_cli_issue(issue, severity, model_path, result)
                    
                    # Add metadata
                    result.metadata["modelscan_version"] = scan_result.get(
                        "modelscan_version", "unknown"
                    )
                    result.metadata["modelscan_total_scanned"] = scan_result.get(
                        "scanned", {}
                    ).get("total_scanned", 0)
                
                # Check for CLI errors
                if proc.returncode != 0 and proc.stderr:
                    result.add_warning(f"ModelScan CLI: {proc.stderr.strip()}")
                    
            finally:
                # Cleanup temp file
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
        except subprocess.TimeoutExpired:
            result.add_error("ModelScan CLI timed out")
        except json.JSONDecodeError as e:
            result.add_error(f"Failed to parse ModelScan output: {e}")
        except Exception as e:
            logger.error(f"ModelScan CLI error: {e}")
            result.add_error(f"ModelScan CLI failed: {e}")
        
        return result
    
    def _process_issue(
        self, issue: Any, model_path: str, result: ScanResult
    ) -> None:
        """Process a ModelScan issue from Python API."""
        try:
            # Extract issue details
            severity_name = issue.severity.name if hasattr(issue, 'severity') else "MEDIUM"
            severity_score = self.SEVERITY_MAP.get(severity_name, 5.5)
            
            # Get operator details
            details = issue.details if hasattr(issue, 'details') else {}
            module = getattr(details, 'module', 'unknown') if hasattr(details, 'module') else details.get('module', 'unknown')
            operator = getattr(details, 'operator', 'unknown') if hasattr(details, 'operator') else details.get('operator', 'unknown')
            source = getattr(details, 'source', model_path) if hasattr(details, 'source') else details.get('source', model_path)
            
            # Create vulnerability
            vuln = self._create_vulnerability(
                vulnerability_type=f"ModelScan - Unsafe Operator ({severity_name})",
                severity=self._get_severity(severity_name, severity_score),
                description=f"Unsafe operator '{operator}' from module '{module}' detected by ModelScan",
                location={"file": model_path, "source": str(source)},
                evidence={
                    "module": module,
                    "operator": operator,
                    "scanner": "modelscan",
                },
                recommendation=self._get_recommendation(module, operator),
                references=[
                    "https://github.com/protectai/modelscan",
                    "https://research.jfrog.com/model-threats/",
                ],
                cwe_id=self._get_cwe(module),
            )
            result.add_vulnerability(vuln)
            
        except Exception as e:
            logger.warning(f"Failed to process ModelScan issue: {e}")
    
    def _process_cli_issue(
        self,
        issue: Dict[str, Any],
        severity: str,
        model_path: str,
        result: ScanResult
    ) -> None:
        """Process a ModelScan issue from CLI JSON output."""
        try:
            severity_score = self.SEVERITY_MAP.get(severity, 5.5)
            
            module = issue.get("module", "unknown")
            operator = issue.get("operator", "unknown")
            source = issue.get("source", model_path)
            description = issue.get("description", f"Unsafe operator '{operator}'")
            scanner_name = issue.get("scanner", "modelscan")
            
            vuln = self._create_vulnerability(
                vulnerability_type=f"ModelScan - Unsafe Operator ({severity})",
                severity=self._get_severity(severity, severity_score),
                description=description,
                location={"file": model_path, "source": source},
                evidence={
                    "module": module,
                    "operator": operator,
                    "scanner": scanner_name,
                },
                recommendation=self._get_recommendation(module, operator),
                references=[
                    "https://github.com/protectai/modelscan",
                    "https://research.jfrog.com/model-threats/",
                ],
                cwe_id=self._get_cwe(module),
            )
            result.add_vulnerability(vuln)
            
        except Exception as e:
            logger.warning(f"Failed to process ModelScan CLI issue: {e}")
    
    def _get_severity(self, name: str, score: float) -> Severity:
        """Convert severity name and score to Severity object."""
        if name == "CRITICAL":
            return Severity.critical(score)
        elif name == "HIGH":
            return Severity.high(score)
        elif name == "MEDIUM":
            return Severity.medium(score)
        else:
            return Severity.low(score)
    
    def _get_recommendation(self, module: str, operator: str) -> str:
        """Get recommendation based on the detected issue."""
        dangerous_modules = {
            "os": "The 'os' module provides system-level access. Do not load this model.",
            "posix": "POSIX system calls detected. This model may execute shell commands.",
            "nt": "Windows NT system calls detected. This model may execute commands.",
            "subprocess": "Subprocess module can execute arbitrary commands. Do not load.",
            "socket": "Network socket access detected. Model may exfiltrate data.",
            "builtins": "Built-in function access detected. Potential code execution.",
            "__builtin__": "Built-in function access detected. Potential code execution.",
            "sys": "System module access. May modify Python runtime.",
            "shutil": "File operation module. May delete or modify files.",
            "Keras": "Keras Lambda layer detected. Review the lambda function code.",
            "Tensorflow": "TensorFlow operation detected. Review for file access.",
        }
        
        base_recommendation = dangerous_modules.get(
            module,
            f"Unsafe operator '{operator}' from '{module}' detected."
        )
        
        return (
            f"{base_recommendation} "
            "Verify the model source and consider using safer alternatives like SafeTensors."
        )
    
    def _get_cwe(self, module: str) -> str:
        """Get CWE ID based on the module."""
        cwe_map = {
            "os": "CWE-78",  # OS Command Injection
            "posix": "CWE-78",
            "nt": "CWE-78",
            "subprocess": "CWE-78",
            "socket": "CWE-918",  # SSRF
            "builtins": "CWE-94",  # Code Injection
            "__builtin__": "CWE-94",
            "sys": "CWE-94",
            "shutil": "CWE-73",  # External Control of File Name
            "Keras": "CWE-94",
            "Tensorflow": "CWE-73",
        }
        return cwe_map.get(module, "CWE-502")  # Default: Deserialization


def is_modelscan_available() -> bool:
    """Check if ModelScan is available (API or CLI)."""
    return MODELSCAN_AVAILABLE or MODELSCAN_CLI_AVAILABLE


def get_modelscan_version() -> Optional[str]:
    """Get the installed ModelScan version."""
    if MODELSCAN_AVAILABLE:
        try:
            from modelscan._version import __version__
            return __version__
        except ImportError:
            pass
    
    if MODELSCAN_CLI_AVAILABLE:
        try:
            result = subprocess.run(
                ["modelscan", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
    
    return None
