"""External reference injection scanner."""

import json
import os
import re
import zipfile
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class ExternalRefScanner(BaseScanner):
    """Scanner for external reference injection vulnerabilities.
    
    Detects URLs and external references in model files that could be
    used for SSRF attacks or to download malicious payloads.
    """
    
    # URL patterns
    URL_PATTERNS = [
        # HTTP/HTTPS URLs
        re.compile(rb'https?://[^\s\x00-\x1f"\'<>\[\]{}|\\^`]{4,500}', re.IGNORECASE),
        # FTP URLs
        re.compile(rb'ftp://[^\s\x00-\x1f"\'<>\[\]{}|\\^`]{4,200}', re.IGNORECASE),
        # File URLs
        re.compile(rb'file://[^\s\x00-\x1f"\'<>\[\]{}|\\^`]{4,200}', re.IGNORECASE),
        # S3 URLs
        re.compile(rb's3://[^\s\x00-\x1f"\'<>\[\]{}|\\^`]{4,200}', re.IGNORECASE),
        # GCS URLs
        re.compile(rb'gs://[^\s\x00-\x1f"\'<>\[\]{}|\\^`]{4,200}', re.IGNORECASE),
    ]
    
    # SSRF-indicative patterns (internal/private networks)
    SSRF_PATTERNS = [
        re.compile(rb'https?://localhost[:/]', re.IGNORECASE),
        re.compile(rb'https?://127\.0\.0\.1[:/]', re.IGNORECASE),
        re.compile(rb'https?://\[::1\]', re.IGNORECASE),
        re.compile(rb'https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE),
        re.compile(rb'https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', re.IGNORECASE),
        re.compile(rb'https?://192\.168\.\d{1,3}\.\d{1,3}', re.IGNORECASE),
        re.compile(rb'https?://169\.254\.\d{1,3}\.\d{1,3}', re.IGNORECASE),  # Link-local
        re.compile(rb'https?://metadata\.google\.internal', re.IGNORECASE),  # GCP metadata
        re.compile(rb'https?://169\.254\.169\.254', re.IGNORECASE),  # AWS/Azure metadata
    ]
    
    # Safe domains that are expected in ML models
    SAFE_DOMAINS = {
        "huggingface.co",
        "cdn.huggingface.co",
        "github.com",
        "raw.githubusercontent.com",
        "pytorch.org",
        "download.pytorch.org",
        "tensorflow.org",
        "storage.googleapis.com",
        "apache.org",
    }
    
    def get_name(self) -> str:
        return "External Reference Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return ["*"]  # Scan all formats
    
    def get_description(self) -> str:
        return "Detects external URLs and references that could enable SSRF or payload download"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a model file for external references."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        # Get allowed domains from config
        allowed_domains = set(
            self.config.get("allowed_domains", []) +
            list(self.SAFE_DOMAINS)
        )
        
        if os.path.isdir(model_path):
            self._scan_directory(model_path, allowed_domains, result)
        else:
            self._scan_file(model_path, allowed_domains, result)
        
        return result
    
    def _scan_directory(
        self,
        dir_path: str,
        allowed_domains: Set[str],
        result: ScanResult
    ):
        """Scan all files in a directory."""
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                self._scan_file(file_path, allowed_domains, result)
    
    def _scan_file(
        self,
        file_path: str,
        allowed_domains: Set[str],
        result: ScanResult
    ):
        """Scan a single file for external references."""
        # Try to read as ZIP first
        if zipfile.is_zipfile(file_path):
            self._scan_zip_file(file_path, allowed_domains, result)
            return
        
        # Read raw file
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except IOError as e:
            result.add_warning(f"Failed to read file: {e}")
            return
        
        self._analyze_content(content, file_path, allowed_domains, result)
    
    def _scan_zip_file(
        self,
        file_path: str,
        allowed_domains: Set[str],
        result: ScanResult
    ):
        """Scan contents of a ZIP file."""
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for name in zf.namelist():
                    try:
                        content = zf.read(name)
                        self._analyze_content(
                            content,
                            f"{file_path}:{name}",
                            allowed_domains,
                            result
                        )
                    except Exception:
                        continue
        except Exception as e:
            result.add_warning(f"Failed to scan ZIP: {e}")
    
    def _analyze_content(
        self,
        content: bytes,
        source: str,
        allowed_domains: Set[str],
        result: ScanResult
    ):
        """Analyze content for external references."""
        # Check for SSRF patterns first (these are always dangerous)
        ssrf_urls = []
        for pattern in self.SSRF_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                try:
                    url = match.decode("utf-8", errors="replace")
                    ssrf_urls.append(url)
                except Exception:
                    continue
        
        if ssrf_urls:
            vuln = self._create_vulnerability(
                vulnerability_type="External Reference - SSRF Vector",
                severity=Severity.high(7.5),
                description=(
                    f"Model contains URLs pointing to internal/private networks. "
                    f"This could enable Server-Side Request Forgery (SSRF) attacks."
                ),
                location={"file": source},
                evidence={
                    "ssrf_urls": list(set(ssrf_urls))[:10],
                    "total_found": len(ssrf_urls),
                },
                recommendation=(
                    "Do not load this model in an environment with internal network access. "
                    "These URLs may be used to access cloud metadata services or internal APIs."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
                ],
                cwe_id="CWE-918",
            )
            result.add_vulnerability(vuln)
        
        # Find all external URLs
        all_urls = []
        for pattern in self.URL_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                try:
                    url = match.decode("utf-8", errors="replace")
                    all_urls.append(url)
                except Exception:
                    continue
        
        # Filter out already-reported SSRF URLs
        ssrf_set = set(ssrf_urls)
        external_urls = [u for u in all_urls if u not in ssrf_set]
        
        # Categorize URLs
        unknown_domain_urls = []
        file_urls = []
        
        for url in external_urls:
            # Check for file:// URLs
            if url.lower().startswith("file://"):
                file_urls.append(url)
                continue
            
            # Check if domain is in allowed list
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Remove port if present
                if ":" in domain:
                    domain = domain.split(":")[0]
                
                # Check against allowed domains
                is_allowed = any(
                    domain == allowed or domain.endswith("." + allowed)
                    for allowed in allowed_domains
                )
                
                if not is_allowed and domain:
                    unknown_domain_urls.append(url)
                    
            except Exception:
                unknown_domain_urls.append(url)
        
        # Report file:// URLs
        if file_urls:
            vuln = self._create_vulnerability(
                vulnerability_type="External Reference - Local File Access",
                severity=Severity.high(7.0),
                description=(
                    f"Model contains file:// URLs that may access local filesystem."
                ),
                location={"file": source},
                evidence={
                    "file_urls": list(set(file_urls))[:10],
                },
                recommendation=(
                    "Verify these file paths are expected and safe."
                ),
                references=[],
                cwe_id="CWE-22",
            )
            result.add_vulnerability(vuln)
        
        # Report unknown domain URLs
        if unknown_domain_urls:
            unique_urls = list(set(unknown_domain_urls))
            
            # Extract unique domains
            domains = set()
            for url in unique_urls:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        domains.add(parsed.netloc.split(":")[0])
                except Exception:
                    pass
            
            severity = Severity.medium(5.5) if len(domains) <= 3 else Severity.high(7.0)
            
            vuln = self._create_vulnerability(
                vulnerability_type="External Reference - Unknown Domains",
                severity=severity,
                description=(
                    f"Model contains URLs pointing to {len(domains)} unknown domain(s). "
                    f"These may be used to download malicious payloads at runtime."
                ),
                location={"file": source},
                evidence={
                    "domains": list(domains)[:20],
                    "sample_urls": unique_urls[:10],
                    "total_urls": len(external_urls),
                },
                recommendation=(
                    "Verify these external references are expected. "
                    "Consider adding trusted domains to the allowed list."
                ),
                references=[],
                cwe_id="CWE-829",
            )
            result.add_vulnerability(vuln)
