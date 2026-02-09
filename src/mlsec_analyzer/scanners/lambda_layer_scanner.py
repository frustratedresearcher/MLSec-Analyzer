"""Keras model exploit payload scanner.

Detects malicious payloads in Keras model files that exploit vulnerabilities in
TensorFlow/Keras model loading. The vulnerability exists in keras.models.load_model()
which can execute arbitrary code from Lambda layers and custom objects.

Target Runtime Vulnerabilities:
- CVE-2024-3660: Lambda layer RCE in keras.models.load_model()
- Custom layer/loss/metric/optimizer code execution
- Marshal/bytecode injection
- Safe mode bypass attempts
- get_file() SSRF
- DoS via memory exhaustion
- Config.json injection
"""

import base64
import json
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple, Set

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class LambdaLayerScanner(BaseScanner):
    """Scanner for malicious Keras model exploit payloads.
    
    Detects crafted Keras model files containing code execution payloads that
    exploit TensorFlow/Keras keras.models.load_model(). The vulnerability is
    in Keras model loading which executes Lambda layer code and custom objects.
    
    Exploit payloads detected (and their target vulnerabilities):
    - Lambda layer RCE → targets CVE-2024-3660 in keras.models.load_model()
    - Custom layer/optimizer code execution → targets load_model()
    - Marshal/bytecode injection → targets Python runtime
    - Safe mode bypass → targets Keras safe_mode protection
    - get_file() SSRF → targets keras.utils.get_file()
    - DoS payloads → targets memory allocation in model loading
    - Config.json injection → targets Keras config parsing
    """
    
    # Dangerous code execution patterns
    DANGEROUS_PATTERNS = [
        # System command execution
        (r"\bos\.system\s*\(", "os.system() - command execution", "critical"),
        (r"\bos\.popen\s*\(", "os.popen() - command execution", "critical"),
        (r"\bos\.exec[lvpe]*\s*\(", "os.exec*() - command execution", "critical"),
        (r"\bos\.spawn[lvpe]*\s*\(", "os.spawn*() - command execution", "critical"),
        (r"\bsubprocess\.(run|call|Popen|check_output)", "subprocess - command execution", "critical"),
        (r"\bpty\.spawn\s*\(", "pty.spawn() - shell spawning", "critical"),
        (r"\bcommands\.(getoutput|getstatusoutput)", "commands module - deprecated RCE", "critical"),
        
        # Code execution primitives
        (r"\beval\s*\(", "eval() - arbitrary code execution", "critical"),
        (r"\bexec\s*\(", "exec() - arbitrary code execution", "critical"),
        (r"\bcompile\s*\(", "compile() - code compilation", "high"),
        (r"\b__import__\s*\(", "__import__() - dynamic import", "high"),
        (r"\bimportlib\.import_module", "importlib - dynamic import", "high"),
        
        # Dangerous builtins access
        (r"\b__builtins__", "__builtins__ access", "critical"),
        (r"\b__globals__", "__globals__ access", "critical"),
        (r"\b__subclasses__", "__subclasses__() - class hierarchy access", "critical"),
        (r"\b__mro__", "__mro__ - method resolution order access", "high"),
        (r"\b__code__", "__code__ - bytecode access", "high"),
        (r"\b__reduce__", "__reduce__() - pickle gadget", "critical"),
        
        # Network operations
        (r"\bsocket\.(socket|create_connection)", "socket - network access", "high"),
        (r"\brequests\.(get|post|put|delete)", "requests - HTTP client", "medium"),
        (r"\burllib\.(request|urlopen)", "urllib - HTTP client", "medium"),
        (r"\bhttp\.client", "http.client - HTTP client", "medium"),
        (r"\bftplib\.", "ftplib - FTP client", "medium"),
        (r"\bsmtplib\.", "smtplib - email sending", "medium"),
        
        # File operations
        (r"\bopen\s*\([^)]*['\"][war]", "file write/append operation", "high"),
        (r"\bshutil\.(copy|move|rmtree)", "shutil - file operations", "high"),
        (r"\bos\.(remove|unlink|rmdir)", "os file deletion", "high"),
        (r"\bos\.chmod\s*\(", "os.chmod() - permission change", "high"),
        
        # Serialization (dangerous deserialization)
        (r"\bpickle\.(load|loads)", "pickle deserialization", "critical"),
        (r"\b_pickle\.", "_pickle module", "critical"),
        (r"\bmarshal\.(load|loads)", "marshal deserialization", "critical"),
        (r"\byaml\.(load|unsafe_load)", "YAML deserialization", "critical"),
        (r"\bjsonpickle\.", "jsonpickle", "high"),
        
        # Reverse shell patterns
        (r"socket.*connect.*dup2", "reverse shell pattern", "critical"),
        (r"os\.dup2\(.*fileno", "file descriptor duplication (shell)", "critical"),
        (r"/bin/(ba)?sh", "shell invocation", "critical"),
        (r"nc\s+-[el]", "netcat usage", "critical"),
        
        # Environment access
        (r"\bos\.environ", "environment variable access", "medium"),
        (r"\bos\.getenv\s*\(", "environment variable read", "medium"),
        (r"\bos\.putenv\s*\(", "environment variable write", "high"),
    ]
    
    # Obfuscation patterns
    OBFUSCATION_PATTERNS = [
        (r"base64\.(b64decode|decodebytes)", "base64 decoding (obfuscation)", "high"),
        (r"codecs\.decode\([^)]*rot", "ROT13 decoding (obfuscation)", "high"),
        (r"bytes\.fromhex\s*\(", "hex decoding (obfuscation)", "high"),
        (r"bytearray\.fromhex", "hex decoding (obfuscation)", "high"),
        (r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr", "chr() concatenation (obfuscation)", "high"),
        (r"''.join\s*\(\s*\[.*chr\s*\(", "chr() join obfuscation", "high"),
        (r"\\x[0-9a-fA-F]{2}", "hex escape sequences", "medium"),
        (r"zlib\.(decompress|decompressobj)", "zlib decompression (obfuscation)", "medium"),
        (r"gzip\.(decompress|GzipFile)", "gzip decompression", "medium"),
    ]
    
    # Safe mode bypass patterns
    BYPASS_PATTERNS = [
        (r"enable_unsafe_deserialization", "enable_unsafe_deserialization() call", "critical"),
        (r"safe_mode\s*=\s*False", "safe_mode=False", "critical"),
        (r"['\"](safe_mode|safeMode)['\"].*False", "safe_mode config bypass", "critical"),
        (r"keras\.config\.enable_unsafe", "keras.config bypass", "critical"),
        (r"allow_pickle\s*=\s*True", "allow_pickle=True", "high"),
        (r"trust_remote_code\s*=\s*True", "trust_remote_code=True", "critical"),
    ]
    
    # SSRF/get_file patterns
    SSRF_PATTERNS = [
        (r"get_file\s*\(", "get_file() - potential SSRF", "high"),
        (r"169\.254\.169\.254", "AWS metadata endpoint (SSRF)", "critical"),
        (r"metadata\.google\.internal", "GCP metadata endpoint (SSRF)", "critical"),
        (r"100\.100\.100\.200", "Alibaba metadata endpoint (SSRF)", "critical"),
        (r"file://", "file:// URI scheme", "high"),
        (r"gopher://", "gopher:// URI scheme (SSRF)", "critical"),
        (r"dict://", "dict:// URI scheme (SSRF)", "high"),
        (r"ldap://", "ldap:// URI scheme", "high"),
    ]
    
    # DoS patterns (excessive resource allocation)
    DOS_PATTERNS = [
        (r"units['\"]?\s*[:=]\s*\d{10,}", "excessive units count (DoS)", "high"),
        (r"shape['\"]?\s*[:=]\s*\[\s*\d{10,}", "excessive shape (DoS)", "high"),
        (r"2\s*\*\*\s*(3[0-9]|[4-9][0-9])", "exponential size (DoS)", "high"),
    ]
    
    # Config injection patterns
    CONFIG_INJECTION_PATTERNS = [
        (r"['\"]module['\"]:\s*['\"]os['\"]", "os module injection", "critical"),
        (r"['\"]module['\"]:\s*['\"]subprocess['\"]", "subprocess module injection", "critical"),
        (r"['\"]module['\"]:\s*['\"]builtins['\"]", "builtins module injection", "critical"),
        (r"['\"]class_name['\"]:\s*['\"]system['\"]", "system class injection", "critical"),
        (r"['\"]function['\"]:\s*['\"][^'\"]*__import__", "import in function field", "critical"),
        (r"types\.FunctionType", "FunctionType injection", "critical"),
        (r"types\.CodeType", "CodeType injection", "critical"),
    ]
    
    # Marshal/bytecode patterns
    BYTECODE_PATTERNS = [
        (r"marshal\.(dumps|loads)", "marshal bytecode", "critical"),
        (r"['\"]bytecode['\"]:", "bytecode field in config", "critical"),
        (r"['\"]__code__['\"]:", "__code__ in config", "critical"),
        (r"co_code", "code object access", "critical"),
        (r"types\.CodeType\s*\(", "CodeType instantiation", "critical"),
        (r"types\.FunctionType\s*\(", "FunctionType instantiation", "critical"),
    ]
    
    # Callback RCE patterns
    CALLBACK_PATTERNS = [
        (r"LambdaCallback", "LambdaCallback usage", "high"),
        (r"on_epoch_(begin|end)['\"]:\s*['\"].*import", "callback with import", "critical"),
        (r"on_batch_(begin|end)['\"]:\s*['\"].*os\.", "callback with os module", "critical"),
        (r"on_train_(begin|end)['\"]:\s*['\"].*exec", "callback with exec", "critical"),
    ]
    
    def get_name(self) -> str:
        return "Lambda Layer Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".keras", ".h5", ".hdf5"]
    
    def get_description(self) -> str:
        return "Detects exploit payloads in Keras models that execute code via keras.models.load_model()"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a Keras model for all vulnerability types."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        ext = os.path.splitext(model_path)[1].lower()
        
        # Read raw file content for pattern matching
        try:
            with open(model_path, "rb") as f:
                raw_content = f.read()
            
            # Scan raw content for patterns
            self._scan_raw_content(raw_content, model_path, result)
        except IOError as e:
            result.add_warning(f"Failed to read file: {e}")
        
        # Format-specific scanning
        if ext == ".keras":
            self._scan_keras_v3(model_path, result)
        elif ext in [".h5", ".hdf5"]:
            self._scan_keras_h5(model_path, result)
        
        return result
    
    def _scan_raw_content(self, content: bytes, file_path: str, result: ScanResult):
        """Scan raw file content for exploit patterns."""
        # Convert to string for regex matching
        try:
            text_content = content.decode("utf-8", errors="ignore")
        except Exception:
            text_content = str(content)
        
        # Check all pattern categories
        all_patterns = [
            ("Code Execution", self.DANGEROUS_PATTERNS),
            ("Obfuscation", self.OBFUSCATION_PATTERNS),
            ("Safe Mode Bypass", self.BYPASS_PATTERNS),
            ("SSRF", self.SSRF_PATTERNS),
            ("DoS", self.DOS_PATTERNS),
            ("Config Injection", self.CONFIG_INJECTION_PATTERNS),
            ("Bytecode", self.BYTECODE_PATTERNS),
            ("Callback", self.CALLBACK_PATTERNS),
        ]
        
        found_patterns: Set[str] = set()
        
        for category, patterns in all_patterns:
            for pattern, description, severity_level in patterns:
                try:
                    if re.search(pattern, text_content, re.IGNORECASE):
                        pattern_key = f"{category}:{description}"
                        if pattern_key not in found_patterns:
                            found_patterns.add(pattern_key)
                            
                            if severity_level == "critical":
                                severity = Severity.critical(9.5)
                            elif severity_level == "high":
                                severity = Severity.high(7.5)
                            else:
                                severity = Severity.medium(5.5)
                            
                            vuln = self._create_vulnerability(
                                vulnerability_type=f"Keras Exploit Payload - {category} (targets load_model())",
                                severity=severity,
                                description=f"File contains exploit payload: {description}. Executes via keras.models.load_model().",
                                location={"file": file_path},
                                evidence={
                                    "category": category,
                                    "pattern": description,
                                    "target_runtime": "keras.models.load_model()",
                                },
                                recommendation=self._get_recommendation(category),
                                references=self._get_references(category),
                                cwe_id=self._get_cwe(category),
                            )
                            result.add_vulnerability(vuln)
                except re.error:
                    continue
    
    def _scan_keras_v3(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a Keras v3 model (.keras ZIP archive)."""
        try:
            if not zipfile.is_zipfile(file_path):
                result.add_error("File is not a valid Keras v3 archive")
                return result
            
            with zipfile.ZipFile(file_path, "r") as zf:
                # Check for path traversal in archive entries
                for name in zf.namelist():
                    if ".." in name or name.startswith("/") or name.startswith("\\"):
                        vuln = self._create_vulnerability(
                            vulnerability_type="Keras - ZIP Path Traversal",
                            severity=Severity.high(8.0),
                            description=f"Archive contains path traversal: {name}",
                            location={"file": file_path, "entry": name},
                            evidence={"malicious_path": name},
                            recommendation="Do not extract this archive.",
                            references=["https://snyk.io/research/zip-slip-vulnerability"],
                            cwe_id="CWE-22",
                        )
                        result.add_vulnerability(vuln)
                
                # Look for config.json
                for name in zf.namelist():
                    if name.endswith("config.json") or name == "config.json":
                        try:
                            config_content = zf.read(name).decode("utf-8")
                            config_data = json.loads(config_content)
                            
                            # Scan config for patterns
                            self._scan_raw_content(
                                config_content.encode(),
                                f"{file_path}:{name}",
                                result
                            )
                            
                            # Analyze the config structure
                            self._analyze_config(config_data, file_path, name, result)
                            
                        except json.JSONDecodeError as e:
                            result.add_warning(f"Failed to parse {name}: {e}")
                        except Exception as e:
                            result.add_warning(f"Error analyzing {name}: {e}")
                            
        except zipfile.BadZipFile:
            result.add_error("Invalid ZIP archive")
        except Exception as e:
            result.add_error(f"Failed to scan Keras v3 file: {e}")
        
        return result
    
    def _scan_keras_h5(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a Keras HDF5 model (.h5/.hdf5)."""
        try:
            import h5py
        except ImportError:
            result.add_warning("h5py is required for full HDF5 scanning")
            return result
        
        try:
            with h5py.File(file_path, "r") as f:
                # Check for pickle data (dangerous)
                self._check_for_pickle(f, file_path, result)
                
                # Look for model config in attributes
                if "model_config" in f.attrs:
                    config_str = f.attrs["model_config"]
                    if isinstance(config_str, bytes):
                        config_str = config_str.decode("utf-8")
                    
                    # Scan config for patterns
                    self._scan_raw_content(
                        config_str.encode(),
                        f"{file_path}:model_config",
                        result
                    )
                    
                    try:
                        config_data = json.loads(config_str)
                        self._analyze_config(config_data, file_path, "model_config", result)
                    except json.JSONDecodeError as e:
                        result.add_warning(f"Failed to parse model_config: {e}")
                
                # Check for Lambda layers in the structure
                self._scan_h5_recursive(f, file_path, result)
                
        except Exception as e:
            result.add_error(f"Failed to scan HDF5 file: {e}")
        
        return result
    
    def _check_for_pickle(self, h5_file, file_path: str, result: ScanResult):
        """Check for pickle data in HDF5 attributes."""
        def check_attrs(obj, path=""):
            if hasattr(obj, "attrs"):
                for attr_name in obj.attrs.keys():
                    try:
                        attr_value = obj.attrs[attr_name]
                        if isinstance(attr_value, bytes):
                            # Check for pickle magic bytes
                            if attr_value.startswith(b'\x80\x04') or attr_value.startswith(b'\x80\x05'):
                                vuln = self._create_vulnerability(
                                    vulnerability_type="Keras HDF5 - Pickle Data Detected",
                                    severity=Severity.critical(9.5),
                                    description=(
                                        f"HDF5 attribute contains pickle data which can execute "
                                        f"arbitrary code. Path: {path}/{attr_name}"
                                    ),
                                    location={"file": file_path, "path": f"{path}/{attr_name}"},
                                    evidence={"pickle_header": attr_value[:20].hex()},
                                    recommendation="Do not load this model. Pickle data is dangerous.",
                                    references=["https://github.com/trailofbits/fickling"],
                                    cwe_id="CWE-502",
                                )
                                result.add_vulnerability(vuln)
                    except Exception:
                        pass
            
            if hasattr(obj, "keys"):
                for key in obj.keys():
                    try:
                        check_attrs(obj[key], f"{path}/{key}")
                    except Exception:
                        pass
        
        check_attrs(h5_file)
    
    def _scan_h5_recursive(self, group, file_path: str, result: ScanResult, path: str = ""):
        """Recursively scan HDF5 groups for Lambda layer config."""
        for key in group.keys():
            try:
                item = group[key]
                current_path = f"{path}/{key}" if path else key
                
                if hasattr(item, "attrs"):
                    for attr_name in item.attrs.keys():
                        attr_value = item.attrs[attr_name]
                        if isinstance(attr_value, bytes):
                            try:
                                attr_str = attr_value.decode("utf-8")
                                
                                # Check for Lambda layer
                                if "lambda" in attr_str.lower() or "Lambda" in attr_str:
                                    try:
                                        config_data = json.loads(attr_str)
                                        self._analyze_config(
                                            config_data, file_path, current_path, result
                                        )
                                    except json.JSONDecodeError:
                                        pass
                                
                                # Check for marshal/bytecode
                                if "marshal" in attr_str or "bytecode" in attr_str:
                                    vuln = self._create_vulnerability(
                                        vulnerability_type="Keras HDF5 - Bytecode in Attribute",
                                        severity=Severity.critical(9.5),
                                        description=f"Marshal/bytecode detected at {current_path}",
                                        location={"file": file_path, "path": current_path},
                                        evidence={"attribute": attr_name},
                                        recommendation="Do not load this model.",
                                        references=[],
                                        cwe_id="CWE-502",
                                    )
                                    result.add_vulnerability(vuln)
                                    
                            except UnicodeDecodeError:
                                pass
                
                if hasattr(item, "keys"):
                    self._scan_h5_recursive(item, file_path, result, current_path)
            except Exception:
                continue
    
    def _analyze_config(
        self,
        config: Any,
        file_path: str,
        config_path: str,
        result: ScanResult
    ):
        """Analyze model config for Lambda layers and other vulnerabilities."""
        if isinstance(config, dict):
            class_name = config.get("class_name", "")
            module = config.get("module", "")
            
            # Check for Lambda layer
            if class_name == "Lambda":
                self._analyze_lambda_layer(config, file_path, config_path, result)
            
            # Check for dangerous module imports
            if module in ("os", "subprocess", "builtins", "sys", "socket"):
                vuln = self._create_vulnerability(
                    vulnerability_type="Keras - Dangerous Module Import",
                    severity=Severity.critical(9.8),
                    description=f"Config imports dangerous module: {module}",
                    location={"file": file_path, "config_path": config_path},
                    evidence={"module": module, "class": class_name},
                    recommendation="Do not load this model.",
                    references=[],
                    cwe_id="CWE-94",
                )
                result.add_vulnerability(vuln)
            
            # Check for enable_unsafe_deserialization
            if class_name == "enable_unsafe_deserialization":
                vuln = self._create_vulnerability(
                    vulnerability_type="Keras - Safe Mode Bypass",
                    severity=Severity.critical(9.5),
                    description="Config attempts to enable unsafe deserialization",
                    location={"file": file_path, "config_path": config_path},
                    evidence={"config": config},
                    recommendation="This model attempts to bypass Keras safe mode.",
                    references=[],
                    cwe_id="CWE-502",
                )
                result.add_vulnerability(vuln)
            
            # Check for custom objects
            if class_name in ("Custom", "CustomObject") or "custom" in module.lower():
                self._analyze_custom_layer(config, file_path, config_path, result)
            
            # Check for get_file
            if "get_file" in str(config) or "weights_url" in config:
                url = config.get("weights_url", config.get("origin", ""))
                if url:
                    self._check_ssrf_url(url, file_path, config_path, result)
            
            # Check for DoS patterns
            inner_config = config.get("config", {})
            if isinstance(inner_config, dict):
                units = inner_config.get("units", 0)
                if isinstance(units, int) and units > 1000000000:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Keras - DoS via Large Layer",
                        severity=Severity.high(7.5),
                        description=f"Layer declares {units:,} units - potential DoS",
                        location={"file": file_path, "config_path": config_path},
                        evidence={"units": units},
                        recommendation="This model may cause memory exhaustion.",
                        references=[],
                        cwe_id="CWE-400",
                    )
                    result.add_vulnerability(vuln)
            
            # Check for callbacks
            if "callbacks" in config:
                self._analyze_callbacks(config["callbacks"], file_path, config_path, result)
            
            # Recursively check nested configs
            for key, value in config.items():
                if key in ("config", "layers", "build_config", "model", "inner_model"):
                    self._analyze_config(value, file_path, f"{config_path}/{key}", result)
        
        elif isinstance(config, list):
            for i, item in enumerate(config):
                self._analyze_config(item, file_path, f"{config_path}[{i}]", result)
    
    def _analyze_lambda_layer(
        self,
        layer_config: Dict[str, Any],
        file_path: str,
        config_path: str,
        result: ScanResult
    ):
        """Analyze a Lambda layer configuration."""
        inner_config = layer_config.get("config", {})
        function_data = inner_config.get("function", "")
        
        # Lambda layer detected
        vuln = self._create_vulnerability(
            vulnerability_type="Keras Exploit Payload - Lambda Layer RCE (targets CVE-2024-3660)",
            severity=Severity.high(8.0),
            description=(
                "File contains Lambda layer with executable code. "
                "Executes via keras.models.load_model() exploiting CVE-2024-3660."
            ),
            location={"file": file_path, "config_path": config_path},
            evidence={"layer_config": str(layer_config)[:500], "target_runtime": "keras.models.load_model()"},
            recommendation=(
                "Use safe_mode=True when loading. This model contains executable code. "
                "Verify source before loading. Consider using standard Keras layers."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3660",
                "https://www.kb.cert.org/vuls/id/253266",
            ],
            cwe_id="CWE-94",
            cve_id="CVE-2024-3660",
        )
        result.add_vulnerability(vuln)
        
        # Try to decode and analyze the function
        if function_data:
            decoded = self._decode_lambda_function(function_data)
            if decoded:
                # Check for dangerous patterns
                self._scan_raw_content(
                    decoded.encode() if isinstance(decoded, str) else decoded,
                    f"{file_path}:{config_path}/function",
                    result
                )
    
    def _analyze_custom_layer(
        self,
        layer_config: Dict[str, Any],
        file_path: str,
        config_path: str,
        result: ScanResult
    ):
        """Analyze a custom layer configuration."""
        vuln = self._create_vulnerability(
            vulnerability_type="Keras - Custom Layer Detected",
            severity=Severity.high(7.0),
            description="Model contains a custom layer requiring external code",
            location={"file": file_path, "config_path": config_path},
            evidence={"layer_config": str(layer_config)[:500]},
            recommendation="Verify custom layer code before loading.",
            references=[],
            cwe_id="CWE-94",
        )
        result.add_vulnerability(vuln)
    
    def _analyze_callbacks(
        self,
        callbacks: List[Any],
        file_path: str,
        config_path: str,
        result: ScanResult
    ):
        """Analyze callback configurations."""
        for i, callback in enumerate(callbacks):
            if isinstance(callback, dict):
                class_name = callback.get("class_name", "")
                if class_name == "LambdaCallback":
                    vuln = self._create_vulnerability(
                        vulnerability_type="Keras - LambdaCallback RCE",
                        severity=Severity.critical(9.0),
                        description="LambdaCallback can execute arbitrary code on training events",
                        location={"file": file_path, "config_path": f"{config_path}[{i}]"},
                        evidence={"callback": str(callback)[:500]},
                        recommendation="Do not load models with LambdaCallback from untrusted sources.",
                        references=[],
                        cwe_id="CWE-94",
                    )
                    result.add_vulnerability(vuln)
    
    def _check_ssrf_url(self, url: str, file_path: str, config_path: str, result: ScanResult):
        """Check URL for SSRF patterns."""
        ssrf_indicators = [
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
            "100.100.100.200",  # Alibaba metadata
            "localhost", "127.0.0.1", "0.0.0.0",
            "internal", "private", "intranet",
            "file://", "gopher://", "dict://",
        ]
        
        for indicator in ssrf_indicators:
            if indicator in url.lower():
                vuln = self._create_vulnerability(
                    vulnerability_type="Keras - SSRF in Model Config",
                    severity=Severity.critical(9.0),
                    description=f"Model config contains potential SSRF URL: {url[:100]}",
                    location={"file": file_path, "config_path": config_path},
                    evidence={"url": url, "indicator": indicator},
                    recommendation="Do not load this model.",
                    references=[],
                    cwe_id="CWE-918",
                )
                result.add_vulnerability(vuln)
                return
    
    def _decode_lambda_function(self, function_data: Any) -> Optional[str]:
        """Decode Lambda function data to readable code."""
        if isinstance(function_data, str):
            # Try base64 decoding
            try:
                decoded = base64.b64decode(function_data)
                return decoded.decode("utf-8", errors="replace")
            except Exception:
                return function_data
        
        if isinstance(function_data, dict):
            if "function_name" in function_data:
                return f"Function: {function_data.get('module', '')}.{function_data['function_name']}"
            if "code" in function_data:
                return str(function_data["code"])
            if "bytecode" in function_data:
                return f"Bytecode: {function_data['bytecode'][:100]}"
        
        if isinstance(function_data, (bytes, bytearray)):
            return function_data.decode("utf-8", errors="replace")
        
        return str(function_data) if function_data else None
    
    def _get_recommendation(self, category: str) -> str:
        """Get recommendation based on vulnerability category."""
        recommendations = {
            "Code Execution": "Do not load this model. It contains code execution patterns.",
            "Obfuscation": "Obfuscated code detected. This may hide malicious behavior.",
            "Safe Mode Bypass": "This model attempts to bypass Keras safe mode protections.",
            "SSRF": "Model attempts to access internal/metadata endpoints.",
            "DoS": "Model may cause resource exhaustion. Use resource limits.",
            "Config Injection": "Model config contains code injection attempts.",
            "Bytecode": "Model contains serialized bytecode which can execute arbitrary code.",
            "Callback": "Model contains callbacks that execute custom code.",
        }
        return recommendations.get(category, "Review this model carefully before loading.")
    
    def _get_references(self, category: str) -> List[str]:
        """Get references based on vulnerability category."""
        refs = {
            "Code Execution": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3660",
                "https://www.kb.cert.org/vuls/id/253266",
            ],
            "Safe Mode Bypass": [
                "https://keras.io/api/saving/model_saving_and_loading/",
            ],
            "Bytecode": [
                "https://github.com/trailofbits/fickling",
            ],
        }
        return refs.get(category, [])
    
    def _get_cwe(self, category: str) -> str:
        """Get CWE ID based on vulnerability category."""
        cwes = {
            "Code Execution": "CWE-94",
            "Obfuscation": "CWE-94",
            "Safe Mode Bypass": "CWE-502",
            "SSRF": "CWE-918",
            "DoS": "CWE-400",
            "Config Injection": "CWE-94",
            "Bytecode": "CWE-502",
            "Callback": "CWE-94",
        }
        return cwes.get(category, "CWE-94")
