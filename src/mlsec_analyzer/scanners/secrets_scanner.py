"""Secrets scanner for detecting credentials and API keys in model files.

Integrates with TruffleHog for advanced secret detection and includes
built-in regex patterns for common secret types.
"""

import os
import re
import subprocess
import tempfile
import json
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability

# Try to import trufflehog3
TRUFFLEHOG3_AVAILABLE = False
try:
    import trufflehog3
    from trufflehog3 import search
    TRUFFLEHOG3_AVAILABLE = True
except ImportError:
    pass

# Check if trufflehog CLI is available
TRUFFLEHOG_CLI_AVAILABLE = False
try:
    result = subprocess.run(
        ["trufflehog", "--version"],
        capture_output=True,
        timeout=5
    )
    if result.returncode == 0:
        TRUFFLEHOG_CLI_AVAILABLE = True
except Exception:
    pass


class SecretsScanner(BaseScanner):
    """Scanner for detecting secrets in model files.
    
    Uses TruffleHog (https://github.com/trufflesecurity/trufflehog) when
    available, with fallback to built-in regex patterns for common secrets.
    
    Detects:
    - API keys (AWS, GCP, Azure, OpenAI, HuggingFace, etc.)
    - Private keys (RSA, SSH, PGP)
    - Tokens (JWT, OAuth, Bearer)
    - Passwords and credentials
    - Database connection strings
    - Cloud credentials
    """
    
    # High-entropy patterns that indicate secrets
    SECRET_PATTERNS = {
        # AWS
        "aws_access_key": {
            "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "severity": "critical",
            "description": "AWS Access Key ID",
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
            "severity": "critical",
            "description": "AWS Secret Access Key",
        },
        
        # Google Cloud
        "gcp_api_key": {
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "severity": "critical",
            "description": "Google Cloud API Key",
        },
        "gcp_service_account": {
            "pattern": r'"type"\s*:\s*"service_account"',
            "severity": "high",
            "description": "GCP Service Account JSON",
        },
        
        # Azure
        "azure_storage_key": {
            "pattern": r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86,}",
            "severity": "critical",
            "description": "Azure Storage Account Key",
        },
        "azure_connection_string": {
            "pattern": r"(?i)(?:mongodb|postgresql|mysql|redis|amqp)[+a-z]*://[^\s\"']+@[^\s\"']+",
            "severity": "high",
            "description": "Database Connection String with Credentials",
        },
        
        # OpenAI / AI APIs
        "openai_api_key": {
            "pattern": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
            "severity": "critical",
            "description": "OpenAI API Key",
        },
        "openai_api_key_v2": {
            "pattern": r"sk-proj-[A-Za-z0-9\-_]{80,}",
            "severity": "critical",
            "description": "OpenAI Project API Key",
        },
        "anthropic_api_key": {
            "pattern": r"sk-ant-[A-Za-z0-9\-_]{80,}",
            "severity": "critical",
            "description": "Anthropic API Key",
        },
        "huggingface_token": {
            "pattern": r"hf_[A-Za-z0-9]{34,}",
            "severity": "critical",
            "description": "HuggingFace API Token",
        },
        "cohere_api_key": {
            "pattern": r"(?i)cohere[_\-\.]?(?:api)?[_\-\.]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{40})",
            "severity": "high",
            "description": "Cohere API Key",
        },
        
        # GitHub
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "severity": "critical",
            "description": "GitHub Token",
        },
        "github_oauth": {
            "pattern": r"gho_[A-Za-z0-9]{36}",
            "severity": "critical",
            "description": "GitHub OAuth Token",
        },
        
        # Private Keys
        "private_key_rsa": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "severity": "critical",
            "description": "Private Key (RSA/EC/DSA/OpenSSH)",
        },
        "private_key_pgp": {
            "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "severity": "critical",
            "description": "PGP Private Key",
        },
        
        # JWT and Tokens
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "severity": "high",
            "description": "JWT Token",
        },
        "bearer_token": {
            "pattern": r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
            "severity": "high",
            "description": "Bearer Token",
        },
        
        # Generic API Keys
        "generic_api_key": {
            "pattern": r"(?i)(?:api[_\-\.]?key|apikey|api[_\-\.]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})",
            "severity": "medium",
            "description": "Generic API Key",
        },
        "generic_secret": {
            "pattern": r"(?i)(?:secret|password|passwd|pwd|token|auth)[_\-\.]?(?:key)?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_!@#$%^&*]{8,})",
            "severity": "medium",
            "description": "Generic Secret/Password",
        },
        
        # Database
        "postgres_url": {
            "pattern": r"postgres(?:ql)?://[^\s\"']+:[^\s\"']+@[^\s\"']+",
            "severity": "critical",
            "description": "PostgreSQL Connection URL with Credentials",
        },
        "mysql_url": {
            "pattern": r"mysql://[^\s\"']+:[^\s\"']+@[^\s\"']+",
            "severity": "critical",
            "description": "MySQL Connection URL with Credentials",
        },
        "mongodb_url": {
            "pattern": r"mongodb(?:\+srv)?://[^\s\"']+:[^\s\"']+@[^\s\"']+",
            "severity": "critical",
            "description": "MongoDB Connection URL with Credentials",
        },
        
        # Slack
        "slack_webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            "severity": "high",
            "description": "Slack Webhook URL",
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            "severity": "critical",
            "description": "Slack Token",
        },
        
        # Stripe
        "stripe_key": {
            "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
            "severity": "critical",
            "description": "Stripe API Key",
        },
        
        # SendGrid
        "sendgrid_key": {
            "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
            "severity": "high",
            "description": "SendGrid API Key",
        },
        
        # Twilio
        "twilio_key": {
            "pattern": r"SK[a-f0-9]{32}",
            "severity": "high",
            "description": "Twilio API Key",
        },
        
        # Discord
        "discord_token": {
            "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
            "severity": "critical",
            "description": "Discord Bot Token",
        },
        "discord_webhook": {
            "pattern": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            "severity": "high",
            "description": "Discord Webhook URL",
        },
        
        # npm
        "npm_token": {
            "pattern": r"npm_[A-Za-z0-9]{36}",
            "severity": "critical",
            "description": "npm Access Token",
        },
        
        # PyPI
        "pypi_token": {
            "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
            "severity": "critical",
            "description": "PyPI API Token",
        },
    }
    
    # File patterns that commonly contain secrets
    SENSITIVE_FILE_PATTERNS = [
        r"\.env$",
        r"\.env\.[a-z]+$",
        r"credentials\.json$",
        r"secrets\.json$",
        r"config\.json$",
        r"\.pem$",
        r"\.key$",
        r"id_rsa$",
        r"id_dsa$",
        r"id_ecdsa$",
        r"id_ed25519$",
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self._compiled_patterns = {}
        for name, info in self.SECRET_PATTERNS.items():
            try:
                self._compiled_patterns[name] = re.compile(info["pattern"])
            except re.error:
                pass
    
    def get_name(self) -> str:
        return "Secrets Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return ["*"]  # Scan all formats
    
    def get_description(self) -> str:
        desc = "Detects secrets, API keys, and credentials embedded in model files"
        if TRUFFLEHOG_CLI_AVAILABLE:
            desc += " (with TruffleHog CLI)"
        elif TRUFFLEHOG3_AVAILABLE:
            desc += " (with trufflehog3)"
        return desc
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a model file for secrets."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        if os.path.isdir(model_path):
            return self._scan_directory(model_path, result)
        
        # Check if it's an archive
        ext = os.path.splitext(model_path)[1].lower()
        if ext in [".zip", ".pth", ".pt", ".keras", ".npz", ".whl"]:
            return self._scan_archive(model_path, result)
        
        return self._scan_file(model_path, result)
    
    def _scan_file(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a single file for secrets."""
        # Try TruffleHog CLI first (most comprehensive)
        if TRUFFLEHOG_CLI_AVAILABLE:
            self._scan_with_trufflehog_cli(file_path, result)
        
        # Also run our regex patterns
        self._scan_with_regex(file_path, result)
        
        return result
    
    def _scan_archive(self, archive_path: str, result: ScanResult) -> ScanResult:
        """Scan files within an archive for secrets."""
        try:
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for name in zf.namelist():
                        # Check for sensitive file names
                        for pattern in self.SENSITIVE_FILE_PATTERNS:
                            if re.search(pattern, name, re.IGNORECASE):
                                vuln = self._create_vulnerability(
                                    vulnerability_type="Secrets - Sensitive File in Archive",
                                    severity=Severity.high(7.5),
                                    description=f"Archive contains potentially sensitive file: {name}",
                                    location={"file": archive_path, "archive_member": name},
                                    evidence={"filename": name, "pattern": pattern},
                                    recommendation="Review and remove sensitive files before distribution.",
                                    references=["https://github.com/trufflesecurity/trufflehog"],
                                    cwe_id="CWE-312",
                                )
                                result.add_vulnerability(vuln)
                        
                        # Extract and scan text-like files
                        if self._is_scannable_archive_member(name):
                            try:
                                content = zf.read(name)
                                # Try to decode as text
                                try:
                                    text_content = content.decode("utf-8", errors="ignore")
                                    self._scan_content(
                                        text_content,
                                        f"{archive_path}:{name}",
                                        result
                                    )
                                except Exception:
                                    pass
                            except Exception:
                                pass
        except Exception as e:
            result.add_warning(f"Failed to scan archive: {e}")
        
        return result
    
    def _scan_directory(self, dir_path: str, result: ScanResult) -> ScanResult:
        """Scan all files in a directory for secrets."""
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                self._scan_file(file_path, result)
        return result
    
    def _scan_with_trufflehog_cli(self, file_path: str, result: ScanResult):
        """Use TruffleHog CLI for comprehensive secret scanning."""
        try:
            # Create temp directory for file-based scanning
            cmd = [
                "trufflehog", "filesystem",
                "--json",
                "--no-update",
                file_path
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if proc.stdout:
                # TruffleHog outputs JSON lines
                for line in proc.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        self._process_trufflehog_finding(finding, file_path, result)
                    except json.JSONDecodeError:
                        pass
                        
        except subprocess.TimeoutExpired:
            result.add_warning("TruffleHog scan timed out")
        except Exception as e:
            result.add_warning(f"TruffleHog CLI scan failed: {e}")
    
    def _process_trufflehog_finding(
        self,
        finding: Dict[str, Any],
        file_path: str,
        result: ScanResult
    ):
        """Process a finding from TruffleHog CLI."""
        detector_name = finding.get("DetectorName", "Unknown")
        raw_secret = finding.get("Raw", "")
        verified = finding.get("Verified", False)
        
        # Determine severity based on verification and type
        if verified:
            severity = Severity.critical(9.5)
            description = f"VERIFIED {detector_name} secret detected by TruffleHog"
        else:
            severity = Severity.high(8.0)
            description = f"Potential {detector_name} secret detected by TruffleHog"
        
        # Redact the secret for safety
        redacted = self._redact_secret(raw_secret)
        
        vuln = self._create_vulnerability(
            vulnerability_type=f"Secrets - {detector_name} (TruffleHog)",
            severity=severity,
            description=description,
            location={
                "file": file_path,
                "line": finding.get("SourceMetadata", {}).get("line"),
            },
            evidence={
                "detector": detector_name,
                "verified": verified,
                "redacted_secret": redacted,
                "source": finding.get("SourceMetadata", {}),
            },
            recommendation=(
                "Immediately rotate this credential. Remove it from the model file "
                "and store secrets securely using environment variables or a secrets manager."
            ),
            references=[
                "https://github.com/trufflesecurity/trufflehog",
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            ],
            cwe_id="CWE-798" if verified else "CWE-312",
        )
        result.add_vulnerability(vuln)
    
    def _scan_with_regex(self, file_path: str, result: ScanResult):
        """Scan file content with regex patterns."""
        try:
            # Read file content
            with open(file_path, "rb") as f:
                content = f.read()
            
            # Try to decode as text
            try:
                text_content = content.decode("utf-8", errors="ignore")
            except Exception:
                text_content = content.decode("latin-1", errors="ignore")
            
            self._scan_content(text_content, file_path, result)
            
        except IOError as e:
            result.add_warning(f"Failed to read file for secret scanning: {e}")
    
    def _scan_content(self, content: str, source: str, result: ScanResult):
        """Scan text content for secrets using regex patterns."""
        # Track found secrets to avoid duplicates
        found_secrets: Set[str] = set()
        
        for name, pattern in self._compiled_patterns.items():
            try:
                matches = pattern.findall(content)
                for match in matches:
                    # Get the matched string
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    
                    # Skip if already found or too short
                    if not match or len(match) < 8:
                        continue
                    
                    # Create a hash to avoid duplicates
                    secret_hash = hash(match)
                    if secret_hash in found_secrets:
                        continue
                    found_secrets.add(secret_hash)
                    
                    info = self.SECRET_PATTERNS[name]
                    severity_level = info["severity"]
                    
                    if severity_level == "critical":
                        severity = Severity.critical(9.0)
                    elif severity_level == "high":
                        severity = Severity.high(7.5)
                    else:
                        severity = Severity.medium(5.5)
                    
                    redacted = self._redact_secret(match)
                    
                    vuln = self._create_vulnerability(
                        vulnerability_type=f"Secrets - {info['description']}",
                        severity=severity,
                        description=f"Detected {info['description']} in model file",
                        location={"file": source},
                        evidence={
                            "pattern_name": name,
                            "redacted_secret": redacted,
                            "secret_length": len(match),
                        },
                        recommendation=(
                            "Remove hardcoded secrets from model files. "
                            "Use environment variables or a secrets manager instead."
                        ),
                        references=[
                            "https://github.com/trufflesecurity/trufflehog",
                            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                        ],
                        cwe_id="CWE-798",
                    )
                    result.add_vulnerability(vuln)
                    
            except Exception:
                pass
    
    def _redact_secret(self, secret: str) -> str:
        """Redact a secret for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
    
    def _is_scannable_archive_member(self, name: str) -> bool:
        """Check if an archive member should be scanned for secrets."""
        scannable_extensions = {
            ".py", ".json", ".yaml", ".yml", ".txt", ".md",
            ".cfg", ".ini", ".conf", ".config", ".env",
            ".sh", ".bash", ".zsh", ".toml", ".xml",
        }
        ext = os.path.splitext(name)[1].lower()
        return ext in scannable_extensions or any(
            re.search(p, name, re.IGNORECASE) 
            for p in self.SENSITIVE_FILE_PATTERNS
        )
