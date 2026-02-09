"""GuardDog integration scanner for dependency security.

Integrates DataDog's GuardDog for malicious package detection.
https://github.com/DataDog/guarddog

GuardDog provides:
- Malicious PyPI package detection
- Typosquatting detection
- Obfuscated code detection
- Data exfiltration detection
- Base64 execution detection
- And many more source code and metadata heuristics

Installation Notes:
- Linux/macOS: pip install guarddog
- Windows: Use Docker image: docker pull ghcr.io/datadog/guarddog
- Or use pre-built CLI from releases
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

# Check if guarddog is available
GUARDDOG_AVAILABLE = False
GUARDDOG_CLI_AVAILABLE = False
GUARDDOG_DOCKER_AVAILABLE = False

try:
    import guarddog
    GUARDDOG_AVAILABLE = True
except ImportError:
    logger.debug("guarddog package not installed")

# Check for CLI availability
try:
    result = subprocess.run(
        ["guarddog", "--help"],
        capture_output=True,
        text=True,
        timeout=10
    )
    if result.returncode == 0:
        GUARDDOG_CLI_AVAILABLE = True
        logger.debug("GuardDog CLI available")
except (subprocess.SubprocessError, FileNotFoundError, OSError):
    pass

# Check for Docker availability as fallback
if not GUARDDOG_CLI_AVAILABLE:
    try:
        result = subprocess.run(
            ["docker", "image", "ls", "ghcr.io/datadog/guarddog"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and "guarddog" in result.stdout:
            GUARDDOG_DOCKER_AVAILABLE = True
            logger.debug("GuardDog Docker image available")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass


class GuardDogScanner(BaseScanner):
    """Scanner that integrates DataDog's GuardDog for dependency security.
    
    GuardDog detects malicious packages using:
    - Source code heuristics (Semgrep rules)
    - Package metadata heuristics
    - Typosquatting detection
    - Obfuscation detection
    - Data exfiltration patterns
    """
    
    # Severity mapping from GuardDog to our format
    SEVERITY_MAP = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 3.0,
        "WARNING": 5.5,
        "ERROR": 7.5,
    }
    
    # GuardDog rule to severity mapping
    RULE_SEVERITY = {
        # Critical: Code execution and data exfiltration
        "code-execution": "CRITICAL",
        "exec-base64": "CRITICAL",
        "exfiltrate-sensitive-data": "CRITICAL",
        "download-executable": "CRITICAL",
        "dll-hijacking": "CRITICAL",
        "steganography": "CRITICAL",
        "cmd-overwrite": "CRITICAL",
        # High: Suspicious behaviors
        "obfuscation": "HIGH",
        "api-obfuscation": "HIGH",
        "silent-process-execution": "HIGH",
        "clipboard-access": "HIGH",
        "shady-links": "HIGH",
        "typosquatting": "HIGH",
        "potentially_compromised_email_domain": "HIGH",
        "unclaimed_maintainer_email_domain": "HIGH",
        # Medium: Metadata issues
        "repository_integrity_mismatch": "MEDIUM",
        "single_python_file": "MEDIUM",
        "bundled_binary": "MEDIUM",
        "release_zero": "MEDIUM",
        "empty_information": "MEDIUM",
        "deceptive_author": "MEDIUM",
    }
    
    def get_name(self) -> str:
        return "GuardDog Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [
            # Dependency files
            ".txt",  # requirements.txt
            ".toml",  # pyproject.toml
            ".cfg",  # setup.cfg
            # Package files
            ".whl",
            ".tar.gz",
            ".zip",
            # Source files (for scanning extracted packages)
            ".py",
        ]
    
    def get_description(self) -> str:
        return (
            "Integrates DataDog GuardDog for malicious package detection "
            "including typosquatting, obfuscation, and data exfiltration"
        )
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan for malicious dependencies using GuardDog."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        # Check if GuardDog is available
        if not GUARDDOG_AVAILABLE and not GUARDDOG_CLI_AVAILABLE and not GUARDDOG_DOCKER_AVAILABLE:
            if sys.platform == "win32":
                warning_msg = (
                    "GuardDog not available. On Windows, use Docker: "
                    "docker pull ghcr.io/datadog/guarddog"
                )
            else:
                warning_msg = "GuardDog not available. Install with: pip install guarddog"
            result.add_warning(warning_msg)
            result.metadata["guarddog_status"] = "unavailable"
            result.metadata["guarddog_warning"] = warning_msg
            return result
        
        # Set status
        if GUARDDOG_CLI_AVAILABLE:
            result.metadata["guarddog_status"] = "cli"
        elif GUARDDOG_DOCKER_AVAILABLE:
            result.metadata["guarddog_status"] = "docker"
        else:
            result.metadata["guarddog_status"] = "python_api"
        
        # Determine what to scan
        path = Path(model_path)
        
        if path.is_dir():
            # Scan directory for dependency files
            return self._scan_directory(model_path, result)
        elif path.name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
            return self._scan_requirements_file(model_path, result)
        elif path.name == "pyproject.toml":
            return self._scan_pyproject(model_path, result)
        elif path.suffix == ".whl":
            return self._scan_wheel(model_path, result)
        elif path.suffix in (".tar.gz", ".tgz"):
            return self._scan_tarball(model_path, result)
        elif path.suffix == ".py":
            return self._scan_python_file(model_path, result)
        else:
            # Check if it's a model package directory
            req_files = ["requirements.txt", "pyproject.toml", "setup.py"]
            for req_file in req_files:
                req_path = path.parent / req_file
                if req_path.exists():
                    return self._scan_requirements_file(str(req_path), result)
        
        result.metadata["guarddog_status"] = "skipped"
        result.metadata["reason"] = "No dependency files found"
        return result
    
    def _scan_directory(self, dir_path: str, result: ScanResult) -> ScanResult:
        """Scan a directory for dependency files."""
        path = Path(dir_path)
        
        # Look for requirements files
        req_files = list(path.glob("requirements*.txt"))
        if req_files:
            for req_file in req_files:
                self._scan_requirements_file(str(req_file), result)
        
        # Look for pyproject.toml
        pyproject = path / "pyproject.toml"
        if pyproject.exists():
            self._scan_pyproject(str(pyproject), result)
        
        return result
    
    def _scan_requirements_file(
        self, file_path: str, result: ScanResult
    ) -> ScanResult:
        """Scan a requirements.txt file using GuardDog verify."""
        result.metadata["guarddog_status"] = "scanning"
        result.metadata["scan_type"] = "requirements_verify"
        
        try:
            # Use GuardDog CLI for verify
            cmd = [
                "guarddog", "pypi", "verify",
                file_path,
                "--output-format", "json",
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=os.path.dirname(file_path) or "."
            )
            
            # Parse JSON output
            if proc.stdout:
                try:
                    findings = json.loads(proc.stdout)
                    self._process_guarddog_findings(findings, file_path, result)
                except json.JSONDecodeError:
                    # Try to parse line by line
                    for line in proc.stdout.strip().split("\n"):
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                self._process_guarddog_findings(finding, file_path, result)
                            except json.JSONDecodeError:
                                continue
            
            if proc.stderr and "error" in proc.stderr.lower():
                result.add_warning(f"GuardDog: {proc.stderr.strip()[:200]}")
            
            result.metadata["guarddog_status"] = "completed"
            
        except subprocess.TimeoutExpired:
            result.add_error("GuardDog scan timed out")
            result.metadata["guarddog_status"] = "timeout"
        except FileNotFoundError:
            result.add_warning("GuardDog CLI not found")
            result.metadata["guarddog_status"] = "cli_not_found"
        except Exception as e:
            logger.error(f"GuardDog scan error: {e}")
            result.add_error(f"GuardDog scan failed: {e}")
            result.metadata["guarddog_status"] = "error"
        
        return result
    
    def _scan_pyproject(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a pyproject.toml for dependencies."""
        # Extract dependencies and scan each one
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                result.add_warning("tomllib/tomli not available for pyproject.toml parsing")
                return result
        
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            
            # Get dependencies from various locations
            dependencies = []
            
            # PEP 621 format
            if "project" in data:
                deps = data["project"].get("dependencies", [])
                dependencies.extend(deps)
                
                optional_deps = data["project"].get("optional-dependencies", {})
                for opt_deps in optional_deps.values():
                    dependencies.extend(opt_deps)
            
            # Poetry format
            if "tool" in data and "poetry" in data["tool"]:
                poetry_deps = data["tool"]["poetry"].get("dependencies", {})
                for pkg in poetry_deps.keys():
                    if pkg != "python":
                        dependencies.append(pkg)
                
                dev_deps = data["tool"]["poetry"].get("dev-dependencies", {})
                for pkg in dev_deps.keys():
                    dependencies.append(pkg)
            
            # Scan each dependency
            for dep in dependencies:
                # Extract package name (remove version specifiers)
                pkg_name = dep.split("[")[0].split(">")[0].split("<")[0].split("=")[0].split("!")[0].strip()
                if pkg_name:
                    self._scan_package(pkg_name, file_path, result)
                    
        except Exception as e:
            result.add_warning(f"Failed to parse pyproject.toml: {e}")
        
        return result
    
    def _scan_package(
        self, package_name: str, source_file: str, result: ScanResult
    ) -> None:
        """Scan a single package using GuardDog."""
        try:
            cmd = [
                "guarddog", "pypi", "scan",
                package_name,
                "--output-format", "json",
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout per package
            )
            
            if proc.stdout:
                try:
                    findings = json.loads(proc.stdout)
                    self._process_guarddog_findings(
                        findings, f"{source_file}:{package_name}", result
                    )
                except json.JSONDecodeError:
                    pass
                    
        except subprocess.TimeoutExpired:
            result.add_warning(f"GuardDog scan timed out for {package_name}")
        except Exception as e:
            logger.debug(f"Failed to scan package {package_name}: {e}")
    
    def _scan_wheel(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a wheel file using GuardDog."""
        result.metadata["guarddog_status"] = "scanning"
        result.metadata["scan_type"] = "wheel"
        
        try:
            cmd = [
                "guarddog", "pypi", "scan",
                file_path,
                "--output-format", "json",
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if proc.stdout:
                try:
                    findings = json.loads(proc.stdout)
                    self._process_guarddog_findings(findings, file_path, result)
                except json.JSONDecodeError:
                    pass
            
            result.metadata["guarddog_status"] = "completed"
            
        except subprocess.TimeoutExpired:
            result.add_error("GuardDog wheel scan timed out")
        except Exception as e:
            result.add_error(f"GuardDog wheel scan failed: {e}")
        
        return result
    
    def _scan_tarball(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a tarball package using GuardDog."""
        return self._scan_wheel(file_path, result)  # Same process
    
    def _scan_python_file(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a Python file for malicious patterns."""
        # For individual Python files, we'd need to use Semgrep directly
        # For now, skip individual files - GuardDog is meant for packages
        result.metadata["guarddog_status"] = "skipped"
        result.metadata["reason"] = "Individual Python file scanning not supported"
        return result
    
    def _process_guarddog_findings(
        self,
        findings: Any,
        source: str,
        result: ScanResult
    ) -> None:
        """Process GuardDog findings and add vulnerabilities."""
        if isinstance(findings, dict):
            # Check for package-level results
            if "results" in findings:
                for rule_name, rule_findings in findings.get("results", {}).items():
                    if rule_findings:  # Non-empty findings
                        self._create_vulnerability_from_rule(
                            rule_name, rule_findings, source, result
                        )
            
            # Check for errors
            if "errors" in findings and findings["errors"]:
                for error in findings["errors"]:
                    result.add_warning(f"GuardDog: {error}")
            
            # Handle package scan results
            package_name = findings.get("package", "")
            if "issues" in findings:
                for issue in findings["issues"]:
                    self._create_vulnerability_from_issue(issue, source, result)
        
        elif isinstance(findings, list):
            for finding in findings:
                self._process_guarddog_findings(finding, source, result)
    
    def _create_vulnerability_from_rule(
        self,
        rule_name: str,
        rule_findings: Any,
        source: str,
        result: ScanResult
    ) -> None:
        """Create vulnerability from a GuardDog rule finding."""
        severity_name = self.RULE_SEVERITY.get(rule_name, "MEDIUM")
        severity_score = self.SEVERITY_MAP.get(severity_name, 5.5)
        
        # Get finding details
        if isinstance(rule_findings, list):
            details = rule_findings
        elif isinstance(rule_findings, dict):
            details = [rule_findings]
        else:
            details = [str(rule_findings)]
        
        vuln = self._create_vulnerability(
            vulnerability_type=f"GuardDog - {rule_name}",
            severity=self._get_severity(severity_name, severity_score),
            description=self._get_rule_description(rule_name),
            location={"file": source},
            evidence={
                "rule": rule_name,
                "findings": details[:5] if isinstance(details, list) else details,
            },
            recommendation=self._get_recommendation(rule_name),
            references=[
                "https://github.com/DataDog/guarddog",
                f"https://github.com/DataDog/guarddog#heuristics",
            ],
            cwe_id=self._get_cwe(rule_name),
        )
        result.add_vulnerability(vuln)
    
    def _create_vulnerability_from_issue(
        self,
        issue: Dict[str, Any],
        source: str,
        result: ScanResult
    ) -> None:
        """Create vulnerability from a GuardDog issue."""
        rule_name = issue.get("rule", issue.get("code", "unknown"))
        message = issue.get("message", issue.get("description", ""))
        location = issue.get("location", {})
        
        severity_name = self.RULE_SEVERITY.get(rule_name, "MEDIUM")
        severity_score = self.SEVERITY_MAP.get(severity_name, 5.5)
        
        vuln = self._create_vulnerability(
            vulnerability_type=f"GuardDog - {rule_name}",
            severity=self._get_severity(severity_name, severity_score),
            description=message or self._get_rule_description(rule_name),
            location={
                "file": source,
                "line": location.get("line"),
                "path": location.get("path"),
            },
            evidence={
                "rule": rule_name,
                "issue": issue,
            },
            recommendation=self._get_recommendation(rule_name),
            references=["https://github.com/DataDog/guarddog"],
            cwe_id=self._get_cwe(rule_name),
        )
        result.add_vulnerability(vuln)
    
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
    
    def _get_rule_description(self, rule_name: str) -> str:
        """Get description for a GuardDog rule."""
        descriptions = {
            "code-execution": "Package executes OS commands in setup.py during installation",
            "exec-base64": "Package dynamically executes base64-encoded code",
            "exfiltrate-sensitive-data": "Package reads and exfiltrates sensitive data",
            "download-executable": "Package downloads and executes remote binaries",
            "dll-hijacking": "Package manipulates trusted apps to load malicious DLLs",
            "steganography": "Package retrieves hidden data from images and executes it",
            "cmd-overwrite": "Package overwrites 'install' command in setup.py",
            "obfuscation": "Package uses common obfuscation methods used by malware",
            "api-obfuscation": "Package uses obfuscated API calls",
            "silent-process-execution": "Package silently executes processes",
            "clipboard-access": "Package accesses system clipboard",
            "shady-links": "Package contains URLs with suspicious domains",
            "typosquatting": "Package name is similar to a popular package (typosquatting)",
            "potentially_compromised_email_domain": "Maintainer email domain may be compromised",
            "unclaimed_maintainer_email_domain": "Maintainer email domain is unclaimed",
            "repository_integrity_mismatch": "Package has unexpected files not in repository",
            "single_python_file": "Package has only a single Python file",
            "bundled_binary": "Package bundles binary executables",
            "release_zero": "Package version is 0.0 or 0.0.0",
            "empty_information": "Package has empty description field",
            "deceptive_author": "Package author uses disposable email",
        }
        return descriptions.get(
            rule_name,
            f"GuardDog detected potential malicious pattern: {rule_name}"
        )
    
    def _get_recommendation(self, rule_name: str) -> str:
        """Get recommendation for a GuardDog finding."""
        if rule_name in ("code-execution", "exec-base64", "download-executable"):
            return "Do not install this package. It executes code during installation."
        elif rule_name in ("exfiltrate-sensitive-data", "steganography"):
            return "Do not install this package. It may steal sensitive data."
        elif rule_name == "typosquatting":
            return "Verify the package name. This may be a typosquatting attempt."
        elif rule_name in ("obfuscation", "api-obfuscation"):
            return "Package contains obfuscated code. Review manually before use."
        else:
            return "Review this package carefully before installing."
    
    def _get_cwe(self, rule_name: str) -> str:
        """Get CWE ID for a GuardDog rule."""
        cwe_map = {
            "code-execution": "CWE-94",
            "exec-base64": "CWE-94",
            "download-executable": "CWE-829",
            "dll-hijacking": "CWE-427",
            "exfiltrate-sensitive-data": "CWE-200",
            "steganography": "CWE-506",
            "obfuscation": "CWE-506",
            "typosquatting": "CWE-1357",
            "shady-links": "CWE-829",
            "bundled_binary": "CWE-829",
        }
        return cwe_map.get(rule_name, "CWE-1357")


def is_guarddog_available() -> bool:
    """Check if GuardDog is available (API, CLI, or Docker)."""
    return GUARDDOG_AVAILABLE or GUARDDOG_CLI_AVAILABLE or GUARDDOG_DOCKER_AVAILABLE


def get_guarddog_version() -> Optional[str]:
    """Get the installed GuardDog version."""
    if GUARDDOG_AVAILABLE:
        try:
            import guarddog
            return getattr(guarddog, "__version__", "unknown")
        except Exception:
            pass
    
    if GUARDDOG_CLI_AVAILABLE:
        try:
            result = subprocess.run(
                ["guarddog", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
    
    return None
