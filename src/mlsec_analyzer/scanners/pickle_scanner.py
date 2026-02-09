"""Pickle exploit payload scanner using Fickling.

Detects malicious payloads in pickle files that exploit Python's pickle.load()
deserialization. The pickle FORMAT itself is inherently unsafe by design - 
the vulnerability is in Python's pickle module which executes embedded code.

Target Runtime Vulnerability:
- Python pickle.load() / pickle.loads() - arbitrary code execution via __reduce__
"""

import io
import os
import pickletools
import zipfile
from typing import Any, Dict, List, Set, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability

# Try to import fickling for advanced analysis
FICKLING_AVAILABLE = False
FICKLING_SIMPLE_AVAILABLE = False

try:
    import fickling
    from fickling.fickle import Pickled
    FICKLING_SIMPLE_AVAILABLE = True
    
    # Try the full analysis module (may fail on some Python versions)
    try:
        from fickling.analysis import check_safety, Severity as FicklingSeverity
        FICKLING_AVAILABLE = True
    except Exception:
        # Analysis module may fail due to stdlib_list compatibility
        pass
except ImportError:
    pass


class PickleScanner(BaseScanner):
    """Scanner for malicious pickle exploit payloads.
    
    Uses Fickling (https://github.com/trailofbits/fickling) for advanced
    pickle analysis, decompilation, and malicious code detection.
    
    Detects crafted pickle files containing code execution payloads that
    exploit Python's pickle.load() deserialization. The vulnerability is
    in Python's pickle module itself - it executes embedded __reduce__ code.
    
    Target: Python pickle.load() / pickle.loads() in any application.
    """
    
    # Dangerous opcodes that indicate code execution
    DANGEROUS_OPCODES = {
        "REDUCE",      # Calls __reduce__ method
        "GLOBAL",      # Imports a module
        "STACK_GLOBAL",  # Imports a module (protocol 4+)
        "INST",        # Creates instance
        "OBJ",         # Creates object
        "NEWOBJ",      # Creates new object
        "NEWOBJ_EX",   # Creates new object (extended)
        "BUILD",       # Builds object state
    }
    
    # Import patterns that are almost always malicious
    HIGHLY_DANGEROUS_IMPORTS = {
        ("os", "system"),
        ("os", "popen"),
        ("os", "execl"),
        ("os", "execle"),
        ("os", "execlp"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "execvp"),
        ("os", "spawnl"),
        ("os", "spawnle"),
        ("os", "spawnlp"),
        ("os", "spawnv"),
        ("os", "spawnve"),
        ("os", "spawnvp"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "Popen"),
        ("subprocess", "run"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "compile"),
        ("builtins", "__import__"),
        ("nt", "system"),  # Windows
        ("posix", "system"),  # Unix
        ("commands", "getoutput"),
        ("commands", "getstatusoutput"),
        ("pty", "spawn"),
        ("socket", "socket"),
        ("pickle", "loads"),
        ("_pickle", "loads"),
        ("marshal", "loads"),
        ("ctypes", "CDLL"),
        ("ctypes", "windll"),
        ("ctypes", "oledll"),
    }
    
    # Modules that are generally suspicious
    SUSPICIOUS_MODULES = {
        "os", "subprocess", "sys", "builtins", "commands",
        "pty", "socket", "http", "urllib", "requests",
        "pickle", "_pickle", "marshal", "ctypes",
        "multiprocessing", "threading", "asyncio",
        "importlib", "runpy", "code", "codeop",
    }
    
    def get_name(self) -> str:
        return "Pickle Deserialization Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".pkl", ".pickle", ".pth", ".pt", ".bin", ".joblib"]
    
    def get_description(self) -> str:
        desc = "Detects exploit payloads in pickle files that execute code via Python's pickle.load()"
        if FICKLING_AVAILABLE:
            desc += " (powered by Fickling)"
        return desc
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a pickle file for deserialization vulnerabilities."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        ext = os.path.splitext(model_path)[1].lower()
        
        # Handle PyTorch files (ZIP archives containing pickles)
        if ext in [".pth", ".pt"]:
            return self._scan_pytorch_file(model_path, result)
        
        # Handle regular pickle files
        return self._scan_pickle_file(model_path, result)
    
    def _scan_pickle_file(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a single pickle file."""
        try:
            with open(file_path, "rb") as f:
                pickle_data = f.read()
        except IOError as e:
            result.add_error(f"Failed to read file: {e}")
            return result
        
        # Use Fickling if available for advanced analysis
        if FICKLING_SIMPLE_AVAILABLE:
            self._analyze_with_fickling(pickle_data, file_path, result)
        
        # Also run our custom analysis
        self._analyze_pickle_data(pickle_data, file_path, result)
        
        return result
    
    def _scan_pytorch_file(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a PyTorch file (ZIP archive containing pickles)."""
        try:
            if not zipfile.is_zipfile(file_path):
                # Not a ZIP, try as regular pickle
                return self._scan_pickle_file(file_path, result)
            
            with zipfile.ZipFile(file_path, "r") as zf:
                for name in zf.namelist():
                    # PyTorch stores data in data.pkl or similar
                    if name.endswith((".pkl", "data.pkl", "/data.pkl")):
                        try:
                            pickle_data = zf.read(name)
                            
                            # Use Fickling if available
                            if FICKLING_SIMPLE_AVAILABLE:
                                self._analyze_with_fickling(
                                    pickle_data,
                                    f"{file_path}:{name}",
                                    result
                                )
                            
                            # Also run custom analysis
                            self._analyze_pickle_data(
                                pickle_data,
                                f"{file_path}:{name}",
                                result
                            )
                        except Exception as e:
                            result.add_warning(f"Failed to analyze {name}: {e}")
                            
        except zipfile.BadZipFile:
            # Not a valid ZIP, try as pickle
            return self._scan_pickle_file(file_path, result)
        except Exception as e:
            result.add_error(f"Failed to scan PyTorch file: {e}")
        
        return result
    
    def _analyze_with_fickling(
        self,
        pickle_data: bytes,
        source_path: str,
        result: ScanResult
    ):
        """Analyze pickle data using Fickling's advanced analysis."""
        try:
            # Load pickle with Fickling
            fickled = Pickled.load(io.BytesIO(pickle_data))
            
            # Try to use Fickling's safety analysis if available
            if FICKLING_AVAILABLE:
                try:
                    safety_result = check_safety(fickled)
                    
                    # Map Fickling severity to our severity
                    if safety_result.severity == FicklingSeverity.OVERTLY_MALICIOUS:
                        vuln = self._create_vulnerability(
                            vulnerability_type="Pickle Exploit Payload - Malicious Code (targets pickle.load())",
                            severity=Severity.critical(9.8),
                            description=(
                                f"File contains malicious code that executes via Python's pickle.load(). "
                                f"Fickling analysis: {safety_result.message}"
                            ),
                            location={"file": source_path, "offset": None},
                            evidence={
                                "fickling_severity": "OVERTLY_MALICIOUS",
                                "fickling_analysis": safety_result.message,
                                "target_runtime": "Python pickle.load()",
                            },
                            recommendation=(
                                "DO NOT LOAD with pickle.load(). File contains code execution payload. "
                                "Use SafeTensors or ONNX format instead."
                            ),
                            references=[
                                "https://github.com/trailofbits/fickling",
                            ],
                            cwe_id="CWE-502",
                        )
                        result.add_vulnerability(vuln)
                        
                    elif safety_result.severity == FicklingSeverity.LIKELY_UNSAFE:
                        vuln = self._create_vulnerability(
                            vulnerability_type="Pickle Exploit Payload - Likely Unsafe (targets pickle.load())",
                            severity=Severity.high(8.0),
                            description=(
                                f"File likely contains exploit payload for Python's pickle.load(). "
                                f"Fickling analysis: {safety_result.message}"
                            ),
                            location={"file": source_path, "offset": None},
                            evidence={
                                "fickling_severity": "LIKELY_UNSAFE",
                                "fickling_analysis": safety_result.message,
                                "target_runtime": "Python pickle.load()",
                            },
                            recommendation=(
                                "Review carefully before using pickle.load(). "
                                "Consider using SafeTensors or ONNX instead."
                            ),
                            references=[
                                "https://github.com/trailofbits/fickling",
                            ],
                            cwe_id="CWE-502",
                        )
                        result.add_vulnerability(vuln)
                        
                    elif safety_result.severity == FicklingSeverity.SUSPICIOUS:
                        vuln = self._create_vulnerability(
                            vulnerability_type="Pickle Suspicious Payload - Review Required",
                            severity=Severity.medium(5.5),
                            description=(
                                f"File contains suspicious patterns that may execute via pickle.load(). "
                                f"Fickling analysis: {safety_result.message}"
                            ),
                            location={"file": source_path, "offset": None},
                            evidence={
                                "fickling_severity": "SUSPICIOUS",
                                "fickling_analysis": safety_result.message,
                                "target_runtime": "Python pickle.load()",
                            },
                            recommendation="Review before loading. Suspicious patterns detected.",
                            references=[
                                "https://github.com/trailofbits/fickling",
                            ],
                            cwe_id="CWE-502",
                        )
                        result.add_vulnerability(vuln)
                except Exception as e:
                    result.add_warning(f"Fickling safety analysis failed: {e}")
            
            # Use Fickling's decompilation to extract imports for our analysis
            try:
                import ast as ast_module
                
                # Get the AST and look for dangerous patterns
                pickle_ast = fickled.ast
                decompiled = ast_module.dump(pickle_ast, indent=2)
                result.metadata["fickling_decompiled"] = decompiled[:2000]
                
                # Check for dangerous function calls in the AST
                dangerous_calls = self._find_dangerous_calls_in_ast(pickle_ast)
                
                if dangerous_calls:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Pickle Exploit Payload - Dangerous Function Calls (targets pickle.load())",
                        severity=Severity.critical(9.8),
                        description=(
                            f"File contains code execution payload with dangerous calls: "
                            f"{', '.join(dangerous_calls[:5])}. Executes via Python pickle.load()."
                        ),
                        location={"file": source_path, "offset": None},
                        evidence={
                            "dangerous_calls": dangerous_calls,
                            "decompiled_preview": decompiled[:500],
                            "target_runtime": "Python pickle.load()",
                        },
                        recommendation=(
                            "DO NOT LOAD with pickle.load(). Use SafeTensors or ONNX instead."
                        ),
                        references=[
                            "https://github.com/trailofbits/fickling",
                        ],
                        cwe_id="CWE-502",
                    )
                    result.add_vulnerability(vuln)
                    
            except Exception:
                pass
                
        except Exception as e:
            result.add_warning(f"Fickling analysis failed: {e}")
    
    def _find_dangerous_calls_in_ast(self, pickle_ast) -> List[str]:
        """Find dangerous function calls in Fickling's decompiled AST."""
        import ast as ast_module
        
        dangerous = []
        dangerous_modules = {"os", "subprocess", "sys", "builtins", "pty", "socket", "pickle", "marshal"}
        dangerous_funcs = {"system", "popen", "exec", "eval", "compile", "spawn", "__import__"}
        
        class DangerousFinder(ast_module.NodeVisitor):
            def visit_Call(self, node):
                try:
                    # Check for dangerous function calls
                    if isinstance(node.func, ast_module.Attribute):
                        if isinstance(node.func.value, ast_module.Name):
                            if node.func.value.id in dangerous_modules:
                                dangerous.append(f"{node.func.value.id}.{node.func.attr}")
                    elif isinstance(node.func, ast_module.Name):
                        if node.func.id in dangerous_funcs:
                            dangerous.append(node.func.id)
                except Exception:
                    pass
                self.generic_visit(node)
        
        try:
            DangerousFinder().visit(pickle_ast)
        except Exception:
            pass
        
        return dangerous
    
    def _analyze_pickle_data(
        self,
        pickle_data: bytes,
        source_path: str,
        result: ScanResult
    ) -> ScanResult:
        """Analyze pickle data for vulnerabilities (fallback/additional analysis)."""
        # Extract opcodes
        opcodes = self._extract_opcodes(pickle_data)
        
        # Extract imports
        imports = self._extract_imports(pickle_data)
        
        # Check for dangerous patterns
        dangerous_opcodes = self._find_dangerous_opcodes(opcodes)
        dangerous_imports = self._find_dangerous_imports(imports)
        suspicious_imports = self._find_suspicious_imports(imports)
        
        # Check for obfuscation patterns
        obfuscation = self._detect_obfuscation(pickle_data, opcodes)
        
        # Only create vulnerabilities if Fickling didn't already catch them
        # Check if we already have critical/high vulns from Fickling
        existing_high_vulns = [
            v for v in result.vulnerabilities 
            if v.severity.level in ["Critical", "High"] and "Fickling" in v.vulnerability_type
        ]
        
        if dangerous_imports and not existing_high_vulns:
            vuln = self._create_vulnerability(
                vulnerability_type="Pickle Exploit Payload - Code Execution Imports (targets pickle.load())",
                severity=Severity.critical(9.8),
                description=(
                    f"File contains exploit payload with code execution imports: "
                    f"{', '.join(f'{m}.{f}' for m, f in dangerous_imports)}. "
                    f"Executes when loaded via Python pickle.load()."
                ),
                location={"file": source_path, "offset": None},
                evidence={
                    "dangerous_imports": [f"{m}.{f}" for m, f in dangerous_imports],
                    "opcodes": list(dangerous_opcodes),
                    "target_runtime": "Python pickle.load()",
                },
                recommendation=(
                    "DO NOT LOAD with pickle.load(). Use SafeTensors or ONNX format instead. "
                    "This file contains code execution payload."
                ),
                references=[
                    "https://research.jfrog.com/model-threats/pickle-malcode/",
                    "https://github.com/trailofbits/fickling",
                ],
                cwe_id="CWE-502",
            )
            result.add_vulnerability(vuln)
        
        elif dangerous_opcodes and suspicious_imports and not existing_high_vulns:
            vuln = self._create_vulnerability(
                vulnerability_type="Pickle Suspicious Payload - Review Required (potential pickle.load() exploit)",
                severity=Severity.high(7.5),
                description=(
                    f"File contains suspicious patterns that may exploit pickle.load(). "
                    f"Suspicious modules: {', '.join(m for m, _ in suspicious_imports)}"
                ),
                location={"file": source_path, "offset": None},
                evidence={
                    "suspicious_imports": [f"{m}.{f}" for m, f in suspicious_imports],
                    "dangerous_opcodes": list(dangerous_opcodes),
                    "target_runtime": "Python pickle.load()",
                },
                recommendation=(
                    "Review carefully before using pickle.load(). "
                    "Consider using SafeTensors or ONNX instead."
                ),
                references=[
                    "https://research.jfrog.com/model-threats/pickle-malcode/",
                ],
                cwe_id="CWE-502",
            )
            result.add_vulnerability(vuln)
        
        if obfuscation:
            # Check if we don't already have an obfuscation warning
            existing_obfuscation = [
                v for v in result.vulnerabilities 
                if "obfuscation" in v.vulnerability_type.lower()
            ]
            if not existing_obfuscation:
                vuln = self._create_vulnerability(
                    vulnerability_type="Pickle Deserialization - Obfuscation Detected",
                    severity=Severity.medium(5.5),
                    description=(
                        f"Pickle file shows signs of obfuscation which may indicate malicious intent: "
                        f"{', '.join(obfuscation)}"
                    ),
                    location={"file": source_path, "offset": None},
                    evidence={
                        "obfuscation_patterns": obfuscation,
                    },
                    recommendation=(
                        "Investigate why obfuscation is present. "
                        "Legitimate ML models rarely use obfuscated pickle."
                    ),
                    references=[],
                    cwe_id="CWE-502",
                )
                result.add_vulnerability(vuln)
        
        return result
    
    def _extract_opcodes(self, pickle_data: bytes) -> List[Tuple[str, Any]]:
        """Extract opcodes from pickle data."""
        opcodes = []
        try:
            for opcode, arg, pos in pickletools.genops(io.BytesIO(pickle_data)):
                opcodes.append((opcode.name, arg))
        except Exception:
            pass
        return opcodes
    
    def _extract_imports(self, pickle_data: bytes) -> List[Tuple[str, str]]:
        """Extract module imports from pickle data."""
        imports = []
        try:
            for opcode, arg, pos in pickletools.genops(io.BytesIO(pickle_data)):
                if opcode.name in ("GLOBAL", "STACK_GLOBAL"):
                    if isinstance(arg, str) and "\n" in arg:
                        parts = arg.split("\n", 1)
                        if len(parts) == 2:
                            imports.append((parts[0], parts[1]))
                    elif isinstance(arg, tuple) and len(arg) == 2:
                        imports.append(arg)
        except Exception:
            pass
        return imports
    
    def _find_dangerous_opcodes(self, opcodes: List[Tuple[str, Any]]) -> Set[str]:
        """Find dangerous opcodes in the list."""
        return {name for name, _ in opcodes if name in self.DANGEROUS_OPCODES}
    
    def _find_dangerous_imports(self, imports: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """Find definitely dangerous imports."""
        dangerous = []
        for module, func in imports:
            if (module, func) in self.HIGHLY_DANGEROUS_IMPORTS:
                dangerous.append((module, func))
            elif module in ("builtins", "__builtin__") and func in ("eval", "exec", "compile"):
                dangerous.append((module, func))
        return dangerous
    
    def _find_suspicious_imports(self, imports: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """Find suspicious but not definitely dangerous imports."""
        suspicious = []
        for module, func in imports:
            if module in self.SUSPICIOUS_MODULES:
                if (module, func) not in self.HIGHLY_DANGEROUS_IMPORTS:
                    suspicious.append((module, func))
        return suspicious
    
    def _detect_obfuscation(self, pickle_data: bytes, opcodes: List[Tuple[str, Any]]) -> List[str]:
        """Detect obfuscation patterns."""
        patterns = []
        
        reduce_count = sum(1 for name, _ in opcodes if name == "REDUCE")
        if reduce_count > 10:
            patterns.append(f"Excessive REDUCE opcodes ({reduce_count})")
        
        global_count = sum(1 for name, _ in opcodes if name in ("GLOBAL", "STACK_GLOBAL"))
        if global_count > 20:
            patterns.append(f"Unusual number of GLOBAL imports ({global_count})")
        
        if b"base64" in pickle_data.lower():
            patterns.append("Contains base64 references")
        
        if b"eval(" in pickle_data or b"exec(" in pickle_data:
            patterns.append("Contains eval/exec string patterns")
        
        return patterns
