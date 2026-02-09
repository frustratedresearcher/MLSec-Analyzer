"""Dependency hijacking scanner."""

import json
import os
import re
import zipfile
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class DependencyScanner(BaseScanner):
    """Scanner for dependency hijacking vulnerabilities.
    
    Detects typosquatting, malicious package names, and suspicious
    dependency configurations in model packages.
    """
    
    # Popular packages that are commonly typosquatted
    POPULAR_PACKAGES = {
        # ML/Data Science
        "numpy", "pandas", "scipy", "scikit-learn", "sklearn",
        "tensorflow", "keras", "torch", "pytorch", "torchvision",
        "transformers", "huggingface-hub", "tokenizers",
        "matplotlib", "seaborn", "plotly",
        "xgboost", "lightgbm", "catboost",
        "opencv-python", "pillow", "imageio",
        # General Python
        "requests", "urllib3", "httpx", "aiohttp",
        "flask", "django", "fastapi",
        "pyyaml", "toml", "configparser",
        "cryptography", "pycrypto", "pycryptodome",
        "boto3", "botocore", "awscli",
        "google-cloud-storage", "azure-storage-blob",
    }
    
    # Known malicious package patterns
    MALICIOUS_PATTERNS = [
        # Common typosquatting patterns
        (r"(.+)-python$", "Suffix '-python' often used in typosquatting"),
        (r"^python-(.+)$", "Prefix 'python-' often used in typosquatting"),
        (r"(.+)lib$", "Suffix 'lib' sometimes used in typosquatting"),
        (r"^(.+)-py$", "Suffix '-py' often used in typosquatting"),
        (r"^(.+)\.(.+)$", "Dots in package names are suspicious"),
        # Known malicious naming patterns
        (r"(.+)-(cli|tool|helper|util|utils)$", "Generic utility suffix"),
    ]
    
    # Suspicious repository URLs
    SUSPICIOUS_REPOS = [
        "github.io",  # GitHub Pages (not actual GitHub)
        "githubusercontent.com",  # Direct GitHub file links
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
    ]
    
    def get_name(self) -> str:
        return "Dependency Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".whl", ".zip", ".tar.gz", "directory"]
    
    def get_description(self) -> str:
        return "Detects dependency hijacking, typosquatting, and malicious package references"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan for dependency vulnerabilities."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"Path not found: {model_path}")
            return result
        
        dependencies = []
        
        if os.path.isdir(model_path):
            dependencies = self._extract_deps_from_directory(model_path)
        elif model_path.endswith(".whl"):
            dependencies = self._extract_deps_from_wheel(model_path)
        elif zipfile.is_zipfile(model_path):
            dependencies = self._extract_deps_from_zip(model_path)
        
        if not dependencies:
            return result
        
        # Analyze dependencies
        for dep in dependencies:
            self._analyze_dependency(dep, model_path, result)
        
        return result
    
    def _extract_deps_from_directory(self, dir_path: str) -> List[Dict]:
        """Extract dependencies from a directory."""
        dependencies = []
        
        # Check for requirements.txt
        req_files = [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "requirements.in",
        ]
        
        for req_file in req_files:
            req_path = os.path.join(dir_path, req_file)
            if os.path.exists(req_path):
                deps = self._parse_requirements_txt(req_path)
                dependencies.extend(deps)
        
        # Check for pyproject.toml
        pyproject_path = os.path.join(dir_path, "pyproject.toml")
        if os.path.exists(pyproject_path):
            deps = self._parse_pyproject_toml(pyproject_path)
            dependencies.extend(deps)
        
        # Check for setup.py (just look for install_requires)
        setup_path = os.path.join(dir_path, "setup.py")
        if os.path.exists(setup_path):
            deps = self._parse_setup_py(setup_path)
            dependencies.extend(deps)
        
        return dependencies
    
    def _extract_deps_from_wheel(self, wheel_path: str) -> List[Dict]:
        """Extract dependencies from a wheel file."""
        dependencies = []
        
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("METADATA") or name.endswith("metadata.json"):
                        content = zf.read(name).decode("utf-8", errors="replace")
                        deps = self._parse_wheel_metadata(content)
                        dependencies.extend(deps)
        except Exception:
            pass
        
        return dependencies
    
    def _extract_deps_from_zip(self, zip_path: str) -> List[Dict]:
        """Extract dependencies from a generic ZIP file."""
        dependencies = []
        
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("requirements.txt"):
                        content = zf.read(name).decode("utf-8", errors="replace")
                        deps = self._parse_requirements_content(content)
                        dependencies.extend(deps)
        except Exception:
            pass
        
        return dependencies
    
    def _parse_requirements_txt(self, file_path: str) -> List[Dict]:
        """Parse requirements.txt file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return self._parse_requirements_content(content)
        except Exception:
            return []
    
    def _parse_requirements_content(self, content: str) -> List[Dict]:
        """Parse requirements.txt content."""
        dependencies = []
        
        for line in content.split("\n"):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            # Skip options
            if line.startswith("-"):
                # Check for suspicious index URLs
                if "--index-url" in line or "--extra-index-url" in line:
                    dependencies.append({
                        "name": "__custom_index__",
                        "raw": line,
                        "type": "custom_index",
                    })
                continue
            
            # Parse package specification
            dep = self._parse_requirement_line(line)
            if dep:
                dependencies.append(dep)
        
        return dependencies
    
    def _parse_requirement_line(self, line: str) -> Optional[Dict]:
        """Parse a single requirement line."""
        # Remove environment markers
        if ";" in line:
            line = line.split(";")[0].strip()
        
        # Handle different formats
        # package==1.0.0
        # package>=1.0.0
        # package[extra]==1.0.0
        # git+https://...
        # https://...
        
        if line.startswith(("git+", "http://", "https://")):
            return {
                "name": "__url_dependency__",
                "raw": line,
                "type": "url",
            }
        
        # Parse package name
        match = re.match(r"^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)", line)
        if match:
            name = match.group(1)
            # Remove extras
            if "[" in name:
                name = name.split("[")[0]
            return {
                "name": name.lower(),
                "raw": line,
                "type": "package",
            }
        
        return None
    
    def _parse_pyproject_toml(self, file_path: str) -> List[Dict]:
        """Parse pyproject.toml for dependencies."""
        dependencies = []
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Simple TOML parsing for dependencies
            in_deps = False
            for line in content.split("\n"):
                if "dependencies" in line.lower() and "=" in line:
                    in_deps = True
                    continue
                
                if in_deps:
                    if line.strip().startswith("]"):
                        in_deps = False
                        continue
                    
                    # Extract package name from string
                    match = re.search(r'"([^"]+)"', line)
                    if match:
                        dep = self._parse_requirement_line(match.group(1))
                        if dep:
                            dependencies.append(dep)
        except Exception:
            pass
        
        return dependencies
    
    def _parse_setup_py(self, file_path: str) -> List[Dict]:
        """Parse setup.py for dependencies (simple extraction)."""
        dependencies = []
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Look for install_requires
            match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                deps_str = match.group(1)
                for dep_match in re.finditer(r'["\']([^"\']+)["\']', deps_str):
                    dep = self._parse_requirement_line(dep_match.group(1))
                    if dep:
                        dependencies.append(dep)
        except Exception:
            pass
        
        return dependencies
    
    def _parse_wheel_metadata(self, content: str) -> List[Dict]:
        """Parse wheel METADATA file."""
        dependencies = []
        
        for line in content.split("\n"):
            if line.startswith("Requires-Dist:"):
                dep_str = line[14:].strip()
                dep = self._parse_requirement_line(dep_str)
                if dep:
                    dependencies.append(dep)
        
        return dependencies
    
    def _analyze_dependency(self, dep: Dict, source: str, result: ScanResult):
        """Analyze a single dependency for issues."""
        name = dep.get("name", "")
        raw = dep.get("raw", "")
        dep_type = dep.get("type", "package")
        
        # Check for custom index URLs
        if dep_type == "custom_index":
            vuln = self._create_vulnerability(
                vulnerability_type="Dependency Hijacking - Custom Index",
                severity=Severity.high(7.5),
                description=(
                    f"Dependencies reference a custom package index. "
                    f"This could be used to serve malicious packages."
                ),
                location={"file": source},
                evidence={"raw": raw},
                recommendation=(
                    "Verify the custom index is trusted. "
                    "Consider using only the official PyPI index."
                ),
                references=[],
                cwe_id="CWE-494",
            )
            result.add_vulnerability(vuln)
            return
        
        # Check for URL dependencies
        if dep_type == "url":
            severity = Severity.medium(5.5)
            
            # Check for suspicious URLs
            for pattern in self.SUSPICIOUS_REPOS:
                if pattern in raw.lower():
                    severity = Severity.high(7.0)
                    break
            
            vuln = self._create_vulnerability(
                vulnerability_type="Dependency Hijacking - URL Dependency",
                severity=severity,
                description=(
                    f"Dependencies include a URL-based package. "
                    f"This bypasses PyPI security and could point to malicious code."
                ),
                location={"file": source},
                evidence={"url": raw},
                recommendation=(
                    "Verify the URL points to a trusted source. "
                    "Consider using versioned PyPI packages instead."
                ),
                references=[],
                cwe_id="CWE-829",
            )
            result.add_vulnerability(vuln)
            return
        
        # Check for typosquatting
        typosquat = self._check_typosquatting(name)
        if typosquat:
            target_package, similarity = typosquat
            
            vuln = self._create_vulnerability(
                vulnerability_type="Dependency Hijacking - Typosquatting",
                severity=Severity.high(8.0),
                description=(
                    f"Package '{name}' appears to be a typosquat of '{target_package}' "
                    f"(similarity: {similarity:.0%}). This is a common supply chain attack."
                ),
                location={"file": source},
                evidence={
                    "suspicious_package": name,
                    "likely_target": target_package,
                    "similarity": similarity,
                },
                recommendation=(
                    f"Verify this is the intended package. "
                    f"Consider using '{target_package}' instead."
                ),
                references=[
                    "https://blog.phylum.io/typosquatting-on-pypi",
                ],
                cwe_id="CWE-494",
            )
            result.add_vulnerability(vuln)
            return
        
        # Check for suspicious naming patterns
        for pattern, description in self.MALICIOUS_PATTERNS:
            if re.match(pattern, name, re.IGNORECASE):
                vuln = self._create_vulnerability(
                    vulnerability_type="Dependency Hijacking - Suspicious Name",
                    severity=Severity.medium(5.0),
                    description=(
                        f"Package '{name}' matches suspicious naming pattern: {description}"
                    ),
                    location={"file": source},
                    evidence={"package": name, "pattern": description},
                    recommendation="Verify this package is legitimate.",
                    references=[],
                    cwe_id="CWE-494",
                )
                result.add_vulnerability(vuln)
                break
    
    def _check_typosquatting(self, name: str) -> Optional[Tuple[str, float]]:
        """Check if a package name is a potential typosquat."""
        name_lower = name.lower().replace("-", "").replace("_", "")
        
        best_match = None
        best_similarity = 0.0
        
        for popular in self.POPULAR_PACKAGES:
            popular_normalized = popular.lower().replace("-", "").replace("_", "")
            
            # Skip exact matches
            if name_lower == popular_normalized:
                return None
            
            # Calculate similarity
            similarity = SequenceMatcher(None, name_lower, popular_normalized).ratio()
            
            # Check for common typo patterns
            # - Character swap
            # - Missing character
            # - Extra character
            # - Character substitution
            
            if len(name_lower) == len(popular_normalized):
                # Check for single character difference
                diff_count = sum(1 for a, b in zip(name_lower, popular_normalized) if a != b)
                if diff_count == 1:
                    similarity = max(similarity, 0.95)
            
            elif abs(len(name_lower) - len(popular_normalized)) == 1:
                # Check for missing/extra character
                longer = name_lower if len(name_lower) > len(popular_normalized) else popular_normalized
                shorter = popular_normalized if len(name_lower) > len(popular_normalized) else name_lower
                
                # Try removing each character
                for i in range(len(longer)):
                    if longer[:i] + longer[i+1:] == shorter:
                        similarity = max(similarity, 0.92)
                        break
            
            if similarity > best_similarity and similarity >= 0.85:
                best_match = popular
                best_similarity = similarity
        
        if best_match and best_similarity >= 0.85:
            return (best_match, best_similarity)
        
        return None
