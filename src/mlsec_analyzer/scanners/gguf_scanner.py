"""GGUF format exploit payload scanner.

Detects malicious payloads in GGUF files that exploit vulnerabilities in
parsers/loaders like llama.cpp, llama-cpp-python, and other GGUF consumers.

NOTE: GGUF files themselves are not "vulnerable" - they are data files.
The vulnerabilities exist in the PARSERS that read these files. This scanner
detects crafted payloads that trigger those parser vulnerabilities.

Target Parser Vulnerabilities:
- CVE-2024-21836: n_tensors integer overflow in llama.cpp
- CVE-2024-21802: Tensor dimension overflow in llama.cpp (n_dims > GGML_MAX_DIMS)
- CVE-2024-25123: Jinja2 SSTI in llama-cpp-python chat_template processing
- TALOS-2024-1913: String length buffer overflow in llama.cpp

Optimized for large files (1GB+) with:
- Chunked streaming pattern scanning
- Progress reporting callbacks
- Header-only structural validation
"""

import os
import re
import struct
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


# Default chunk size for streaming reads (8MB for good balance)
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8MB

# Maximum bytes to scan for patterns in very large files (first 100MB + last 50MB)
MAX_PATTERN_SCAN_SIZE = 150 * 1024 * 1024  # 150MB

# Checkpoint save interval (save every 50MB scanned)
CHECKPOINT_INTERVAL = 50 * 1024 * 1024  # 50MB

# Progress callback type
ProgressCallback = Optional[Callable[[str, int, int], None]]

# Checkpoint callback type: (scanner_name, bytes_scanned, total_bytes, vulnerabilities, metadata) -> None
CheckpointCallback = Optional[Callable[[str, int, int, list, dict], None]]


class GGUFScanner(BaseScanner):
    """Scanner for malicious GGUF exploit payloads.
    
    Detects crafted payloads in GGUF files that exploit vulnerabilities in
    parsers like llama.cpp and llama-cpp-python. The GGUF file format itself
    is just data - vulnerabilities exist in the software that parses these files.
    
    Exploit payloads detected (and their target parser vulnerabilities):
    - Jinja2 SSTI payloads → targets CVE-2024-25123 in llama-cpp-python
    - n_tensors overflow → targets CVE-2024-21836 in llama.cpp
    - n_dims overflow → targets CVE-2024-21802 in llama.cpp
    - Signed-to-unsigned conversion exploits → targets llama.cpp memory handling
    - Version corruption markers → parser confusion attacks
    - Metadata count overflow → DoS/crash in llama.cpp
    - String length exploits → buffer overflow in llama.cpp
    - Path traversal patterns → extraction vulnerabilities
    - Memory exhaustion payloads → DoS in parsers
    """
    
    # GGUF magic number
    GGUF_MAGIC = b"GGUF"
    GGML_MAGIC = b"GGML"
    
    # GGUF versions
    GGUF_VERSION_MIN = 1
    GGUF_VERSION_MAX = 3
    
    # GGML maximum dimensions (from ggml.h)
    GGML_MAX_DIMS = 4
    
    # GGUF data types and their sizes
    GGUF_TYPE_SIZES = {
        0: 1,   # GGUF_TYPE_UINT8
        1: 1,   # GGUF_TYPE_INT8
        2: 2,   # GGUF_TYPE_UINT16
        3: 2,   # GGUF_TYPE_INT16
        4: 4,   # GGUF_TYPE_UINT32
        5: 4,   # GGUF_TYPE_INT32
        6: 4,   # GGUF_TYPE_FLOAT32
        7: 1,   # GGUF_TYPE_BOOL
        8: -1,  # GGUF_TYPE_STRING (variable)
        9: -1,  # GGUF_TYPE_ARRAY (variable)
        10: 8,  # GGUF_TYPE_UINT64
        11: 8,  # GGUF_TYPE_INT64
        12: 8,  # GGUF_TYPE_FLOAT64
    }
    
    GGUF_TYPE_NAMES = {
        0: "UINT8", 1: "INT8", 2: "UINT16", 3: "INT16",
        4: "UINT32", 5: "INT32", 6: "FLOAT32", 7: "BOOL",
        8: "STRING", 9: "ARRAY", 10: "UINT64", 11: "INT64", 12: "FLOAT64",
    }
    
    # Maximum reasonable values - anything above these is suspicious
    MAX_TENSOR_COUNT = 100000          # Reasonable limit for tensors
    MAX_KV_COUNT = 100000              # Reasonable limit for metadata
    MAX_STRING_LENGTH = 10 * 1024 * 1024  # 10MB max string
    MAX_ARRAY_LENGTH = 10000000        # 10M elements max
    MAX_TENSOR_DIMS = 4                # GGML_MAX_DIMS
    MAX_DIM_SIZE = 2**40               # ~1 trillion max dimension size
    SIZE_MAX = 2**63 - 1               # For 64-bit systems
    UINT64_MAX = 2**64 - 1             # Maximum uint64 value
    INT32_MAX = 2**31 - 1              # Maximum signed 32-bit
    INT32_MIN = -(2**31)               # Minimum signed 32-bit
    
    # Known exploit values
    EXPLOIT_VALUES = {
        0xDEADBEEF: "Classic debug/exploit marker (DEADBEEF)",
        0xCAFEBABE: "Java class file magic / exploit marker",
        0xBAADF00D: "Bad food - memory debug pattern",
        0xFEEDFACE: "Mach-O magic / exploit marker",
        0x41414141: "AAAA - Buffer overflow pattern",
        0x42424242: "BBBB - Buffer overflow pattern",
        0xFFFFFFFF: "Maximum 32-bit value",
        0xFFFFFFFFFFFFFFFF: "Maximum 64-bit value - integer overflow exploit",
        0x7FFFFFFF: "Maximum signed 32-bit value (INT32_MAX)",
        0x7FFFFFFFFFFFFFFF: "Maximum signed 64-bit value - integer overflow",
        0x1D1D1D1D1D1D1D1D: "CVE-2024-21836 tensor overflow pattern",
        0x80000000: "INT32_MIN as unsigned - sign conversion exploit",
        0x80000001: "INT32_MAX + 2 - sign conversion exploit",
    }
    
    # Signed-to-unsigned exploit values (values that become negative when cast to int32)
    SIGNED_UNSIGNED_EXPLOITS = {
        2147483648: "INT32_MAX + 1 (0x80000000) - becomes negative in signed int32",
        2147483649: "INT32_MAX + 2 (0x80000001) - token memcpy exploit",
        4294967295: "UINT32_MAX - becomes -1 in signed int32",
    }
    
    # Jinja2 SSTI exploit patterns (CVE-2024-25123, llama-cpp-python < 0.2.72)
    # These are combinations that indicate actual exploit code, not vocabulary
    # Each pattern requires template markers + exploit code together
    JINJA2_SSTI_EXPLOIT_PATTERNS = [
        # Python introspection in templates (most common SSTI patterns)
        b"{{.*__class__",
        b"{{.*__mro__",
        b"{{.*__subclasses__",
        b"{{.*__builtins__",
        b"{{.*__import__",
        b"{{.*__globals__",
        b"__class__.*}}",
        b"__globals__.*}}",
        # Direct command execution patterns
        b".popen(",
        b".system(",
        b"os.popen",
        b"os.system",
        b"subprocess.call",
        b"subprocess.Popen",
        b"subprocess.run",
        # Jinja2 specific patterns with actual Python code
        b"{% import",
        b"{% from",
        b"{{config",
        b"{{request",
        b"lipsum.__globals__",
        b"cycler.__init__",
        b"joiner.__init__",
        b"namespace.__init__",
    ]
    
    # Simple template markers (to check if file has templates at all)
    TEMPLATE_MARKERS = [b"{{", b"}}", b"{%", b"%}"]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        rb"\.\./",
        rb"\.\.\\",
        rb"/etc/passwd",
        rb"/etc/shadow",
        rb"C:\\Windows",
        rb"C:/Windows",
        rb"%2e%2e%2f",  # URL encoded ../
        rb"%2e%2e/",
        rb"..%2f",
        rb"%2e%2e%5c",  # URL encoded ..\
    ]
    
    # Dangerous metadata keys that could be exploited
    DANGEROUS_METADATA_KEYS = [
        b"tokenizer.chat_template",  # Jinja2 SSTI target
        b"tokenizer.ggml.tokens",
        b"general.source.url",  # Could be used for SSRF
        b"general.base_model.source.url",
    ]
    
    def get_name(self) -> str:
        return "GGUF Format Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".gguf", ".ggml"]
    
    def get_description(self) -> str:
        return "Detects exploit payloads in GGUF files that target parser vulnerabilities in llama.cpp and similar tools"
    
    def scan(
        self, 
        model_path: str, 
        global_config: Dict[str, Any],
        progress_callback: ProgressCallback = None,
        checkpoint_callback: CheckpointCallback = None,
        resume_from_bytes: int = 0,
    ) -> ScanResult:
        """Scan a GGUF file for vulnerabilities.
        
        Args:
            model_path: Path to the GGUF file
            global_config: Global configuration dictionary
            progress_callback: Optional callback for progress updates
                              signature: (stage: str, current: int, total: int) -> None
            checkpoint_callback: Optional callback to save checkpoints
                              signature: (scanner_name, bytes_scanned, total, vulns, metadata) -> None
            resume_from_bytes: Byte offset to resume from (for interrupted scans)
        
        Returns:
            ScanResult with vulnerabilities found
        """
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        try:
            file_size = os.path.getsize(model_path)
            result.metadata["file_size"] = file_size
            result.metadata["file_size_human"] = self._format_size(file_size)
            
            # Report initial progress
            if progress_callback:
                if resume_from_bytes > 0:
                    progress_callback(f"Resuming GGUF scan from {self._format_size(resume_from_bytes)}", 0, 100)
                else:
                    progress_callback("Starting GGUF scan", 0, 100)
            
            # For large files, use optimized streaming scan
            if file_size > DEFAULT_CHUNK_SIZE:
                self._scan_large_file(
                    model_path, file_size, result, 
                    progress_callback, checkpoint_callback, resume_from_bytes
                )
            else:
                # Small file - read entirely (legacy behavior for speed)
                self._scan_small_file(model_path, file_size, result, progress_callback)
                
        except KeyboardInterrupt:
            # Save checkpoint on interrupt
            if checkpoint_callback:
                checkpoint_callback(
                    self.get_name(),
                    result.metadata.get("bytes_scanned", 0),
                    file_size,
                    result.vulnerabilities,
                    result.metadata,
                )
            result.add_warning("Scan interrupted - checkpoint saved")
            raise
        except Exception as e:
            result.add_error(f"Failed to scan GGUF file: {e}")
        
        if progress_callback:
            progress_callback("Scan complete", 100, 100)
        
        return result
    
    def _format_size(self, size: int) -> str:
        """Format file size in human readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def _scan_small_file(
        self, 
        model_path: str, 
        file_size: int, 
        result: ScanResult,
        progress_callback: ProgressCallback = None,
    ):
        """Scan a small file (< 8MB) by reading entirely into memory."""
        if progress_callback:
            progress_callback("Reading file", 10, 100)
        
        with open(model_path, "rb") as f:
            file_data = f.read()
        
        if progress_callback:
            progress_callback("Scanning for patterns", 30, 100)
        
        # Scan for dangerous patterns
        self._scan_for_jinja2_ssti(file_data, model_path, result)
        self._scan_for_path_traversal(file_data, model_path, result)
        self._scan_for_exploit_patterns(file_data, model_path, result)
        
        if progress_callback:
            progress_callback("Validating structure", 60, 100)
        
        # Scan GGUF structure
        with open(model_path, "rb") as f:
            self._scan_gguf_structure(f, model_path, file_size, file_data, result)
    
    def _scan_large_file(
        self, 
        model_path: str, 
        file_size: int, 
        result: ScanResult,
        progress_callback: ProgressCallback = None,
        checkpoint_callback: CheckpointCallback = None,
        resume_from_bytes: int = 0,
    ):
        """Scan a large file using optimized streaming approach.
        
        Strategy for large files:
        1. Read and validate header structure (first 24 bytes)
        2. Stream through file in chunks for pattern scanning
        3. For very large files (>150MB), only scan first 100MB and last 50MB
        4. Save checkpoints periodically for resumable scanning
        """
        result.metadata["scan_mode"] = "streaming"
        
        if progress_callback:
            progress_callback("Reading header", 5, 100)
        
        # Phase 1: Validate GGUF structure (header only - fast)
        # Always do this even on resume to catch header-based vulnerabilities
        with open(model_path, "rb") as f:
            self._scan_gguf_structure_header_only(f, model_path, file_size, result)
        
        if progress_callback:
            progress_callback("Scanning for exploit patterns", 20, 100)
        
        # Phase 2: Chunked pattern scanning
        self._scan_patterns_chunked(
            model_path, file_size, result, 
            progress_callback, checkpoint_callback, resume_from_bytes
        )
    
    def _scan_gguf_structure_header_only(
        self, 
        f, 
        file_path: str, 
        file_size: int, 
        result: ScanResult
    ):
        """Scan GGUF file structure from header only (no full file read)."""
        # Read and validate magic (offset 0-3)
        magic = f.read(4)
        
        if magic == self.GGML_MAGIC:
            result.add_warning("Legacy GGML format detected - limited vulnerability checking")
            return
        
        if magic != self.GGUF_MAGIC:
            result.add_error("Not a valid GGUF file - invalid magic bytes")
            return
        
        # Read and validate version (offset 4-7)
        version_bytes = f.read(4)
        version = struct.unpack("<I", version_bytes)[0]
        self._check_version(version, file_path, result)
        
        # Read tensor count (offset 8-15)
        tensor_count_bytes = f.read(8)
        tensor_count = struct.unpack("<Q", tensor_count_bytes)[0]
        self._check_tensor_count(tensor_count, file_path, file_size, result)
        
        # Read metadata KV count (offset 16-23)
        kv_count_bytes = f.read(8)
        kv_count = struct.unpack("<Q", kv_count_bytes)[0]
        self._check_kv_count(kv_count, file_path, result)
        
        # For large files, limit metadata parsing to avoid slowdown
        max_metadata_to_parse = min(kv_count, 500)
        if kv_count > 500:
            result.add_warning(f"Large metadata count ({kv_count}), parsing first 500 entries")
        
        # Parse metadata entries (starting at offset 24)
        # We pass None for file_data since we're not doing pattern matching here
        self._check_metadata_entries_fast(f, file_path, max_metadata_to_parse, result)
        
        # Parse tensor info (limited for large files)
        max_tensors_to_parse = min(tensor_count, 500)
        if tensor_count > 500:
            result.add_warning(f"Large tensor count ({tensor_count}), parsing first 500 tensors")
        
        self._check_tensor_info_fast(f, file_path, max_tensors_to_parse, file_size, result)
    
    def _check_metadata_entries_fast(
        self, f, file_path: str, kv_count: int, result: ScanResult
    ):
        """Fast metadata entry checking without full file data."""
        for i in range(kv_count):
            try:
                current_offset = f.tell()
                
                # Read key string length (8 bytes)
                key_length_bytes = f.read(8)
                if len(key_length_bytes) < 8:
                    break
                
                key_length = struct.unpack("<Q", key_length_bytes)[0]
                
                # Check for exploit values
                if key_length in self.SIGNED_UNSIGNED_EXPLOITS:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF Exploit Payload - Signed/Unsigned Conversion (targets llama.cpp)",
                        severity=Severity.critical(9.5),
                        description=(
                            f"File contains exploit payload: Metadata entry {i} has length {key_length} "
                            f"({self.SIGNED_UNSIGNED_EXPLOITS[key_length]}). Triggers signed/unsigned bug in llama.cpp."
                        ),
                        location={"file": file_path, "offset": current_offset, "metadata_index": i},
                        evidence={"length": key_length, "target_parser": "llama.cpp"},
                        recommendation="DO NOT LOAD with vulnerable parsers. File contains exploit payload.",
                        references=[],
                        cwe_id="CWE-195",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                if key_length in self.EXPLOIT_VALUES:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF Exploit Payload - Metadata String Length (targets llama.cpp)",
                        severity=Severity.critical(9.5),
                        description=(
                            f"File contains exploit payload: Metadata entry {i} key length 0x{key_length:016X}. "
                            f"Triggers buffer overflow in llama.cpp parser."
                        ),
                        location={"file": file_path, "offset": current_offset, "metadata_index": i},
                        evidence={"key_length": key_length, "target_parser": "llama.cpp"},
                        recommendation="DO NOT LOAD with vulnerable parsers. File contains exploit payload.",
                        references=[],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Skip key (but cap at reasonable limit)
                skip_len = min(key_length, 100000)
                f.seek(skip_len, 1)
                
                # Read value type
                value_type_bytes = f.read(4)
                if len(value_type_bytes) < 4:
                    break
                
                value_type = struct.unpack("<I", value_type_bytes)[0]
                
                # Skip value based on type
                self._skip_metadata_value(f, value_type)
                
            except struct.error:
                break
            except Exception:
                break
    
    def _skip_metadata_value(self, f, value_type: int):
        """Skip a metadata value without fully validating (for speed)."""
        type_size = self.GGUF_TYPE_SIZES.get(value_type, 0)
        
        if type_size > 0:
            f.seek(type_size, 1)
        elif value_type == 8:  # String
            length_bytes = f.read(8)
            if len(length_bytes) == 8:
                length = struct.unpack("<Q", length_bytes)[0]
                f.seek(min(length, 10 * 1024 * 1024), 1)  # Cap at 10MB
        elif value_type == 9:  # Array
            f.seek(4, 1)  # array type
            length_bytes = f.read(8)
            if len(length_bytes) == 8:
                array_len = struct.unpack("<Q", length_bytes)[0]
                # Skip array elements (estimate)
                f.seek(min(array_len * 8, 10 * 1024 * 1024), 1)
    
    def _check_tensor_info_fast(
        self, f, file_path: str, tensor_count: int, file_size: int, result: ScanResult
    ):
        """Fast tensor info checking."""
        cumulative_size = 0
        
        for i in range(tensor_count):
            try:
                current_offset = f.tell()
                
                # Read tensor name length
                name_length_bytes = f.read(8)
                if len(name_length_bytes) < 8:
                    break
                
                name_length = struct.unpack("<Q", name_length_bytes)[0]
                
                # Check for exploit values
                if name_length in self.EXPLOIT_VALUES or name_length in self.SIGNED_UNSIGNED_EXPLOITS:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF Exploit Payload - Tensor Name Length (targets llama.cpp)",
                        severity=Severity.critical(9.0),
                        description=(
                            f"File contains exploit payload: Tensor {i} name length 0x{name_length:016X}. "
                            f"Triggers buffer overflow in llama.cpp parser."
                        ),
                        location={"file": file_path, "offset": current_offset, "tensor_index": i},
                        evidence={"name_length": name_length, "target_parser": "llama.cpp"},
                        recommendation="DO NOT LOAD with vulnerable parsers. File contains exploit payload.",
                        references=[],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Skip name
                f.seek(min(name_length, 100000), 1)
                
                # Read n_dims
                n_dims_bytes = f.read(4)
                if len(n_dims_bytes) < 4:
                    break
                
                n_dims = struct.unpack("<I", n_dims_bytes)[0]
                
                # CVE-2024-21802 check
                if n_dims > self.GGML_MAX_DIMS:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF Exploit Payload - Tensor Dimension Overflow (targets CVE-2024-21802)",
                        severity=Severity.critical(9.0),
                        description=(
                            f"File contains exploit payload: Tensor {i} has {n_dims} dimensions (max: {self.GGML_MAX_DIMS}). "
                            f"This payload triggers CVE-2024-21802 buffer overflow in llama.cpp parser."
                        ),
                        location={"file": file_path, "offset": current_offset, "tensor_index": i},
                        evidence={"n_dims": n_dims, "max_dims": self.GGML_MAX_DIMS, "target_parser": "llama.cpp"},
                        recommendation="DO NOT LOAD with vulnerable parsers (llama.cpp < 2.0). File contains exploit payload.",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21802"],
                        cwe_id="CWE-122",
                        cve_id="CVE-2024-21802",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Skip dimensions (8 bytes each) + type (4) + offset (8)
                f.seek(n_dims * 8 + 12, 1)
                
            except struct.error:
                break
            except Exception:
                break
    
    def _scan_patterns_chunked(
        self,
        model_path: str,
        file_size: int,
        result: ScanResult,
        progress_callback: ProgressCallback = None,
        checkpoint_callback: CheckpointCallback = None,
        resume_from_bytes: int = 0,
    ):
        """Scan for exploit patterns using chunked reading.
        
        For very large files (>150MB), only scans:
        - First 100MB (where headers and templates usually are)
        - Last 50MB (for any appended payloads)
        
        Supports:
        - Progress reporting via callback
        - Checkpoint saving for resumable scanning
        - Resume from previous checkpoint
        """
        # Track SSTI detection state across chunks
        ssti_context = {
            'keywords_found': [],
            'has_markers': False,
            'reported': False,
        }
        
        # Determine scan ranges
        if file_size <= MAX_PATTERN_SCAN_SIZE:
            # Scan entire file
            scan_ranges = [(0, file_size)]
            result.metadata["pattern_scan_coverage"] = "full"
        else:
            # Scan first 100MB and last 50MB
            first_chunk_size = 100 * 1024 * 1024
            last_chunk_size = 50 * 1024 * 1024
            scan_ranges = [
                (0, first_chunk_size),
                (file_size - last_chunk_size, file_size),
            ]
            result.metadata["pattern_scan_coverage"] = f"first {first_chunk_size//1024//1024}MB + last {last_chunk_size//1024//1024}MB"
            result.add_warning(
                f"Large file ({self._format_size(file_size)}) - pattern scanning limited to "
                f"first 100MB and last 50MB for performance"
            )
        
        total_to_scan = sum(end - start for start, end in scan_ranges)
        bytes_scanned = 0
        chunk_size = DEFAULT_CHUNK_SIZE
        overlap = 1024  # Overlap to catch patterns spanning chunks
        last_checkpoint_bytes = 0
        
        with open(model_path, "rb") as f:
            for range_start, range_end in scan_ranges:
                # Handle resume - skip ranges we've already scanned
                if resume_from_bytes > 0:
                    range_bytes = range_end - range_start
                    if bytes_scanned + range_bytes <= resume_from_bytes:
                        bytes_scanned += range_bytes
                        continue
                    elif bytes_scanned < resume_from_bytes:
                        # Partial resume within this range
                        skip_bytes = resume_from_bytes - bytes_scanned
                        range_start += skip_bytes
                        bytes_scanned = resume_from_bytes
                
                f.seek(range_start)
                position = range_start
                prev_chunk_tail = b""
                
                while position < range_end:
                    # Calculate how much to read
                    remaining = range_end - position
                    read_size = min(chunk_size, remaining)
                    
                    chunk = f.read(read_size)
                    if not chunk:
                        break
                    
                    # Prepend tail from previous chunk for overlap
                    scan_data = prev_chunk_tail + chunk
                    chunk_offset = position - len(prev_chunk_tail)
                    
                    # Scan this chunk
                    self._scan_chunk_for_patterns(
                        scan_data, chunk_offset, model_path, result, ssti_context
                    )
                    
                    # Keep tail for next iteration
                    prev_chunk_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk
                    
                    bytes_scanned += len(chunk)
                    position += len(chunk)
                    
                    # Update progress
                    if progress_callback:
                        pct = 20 + int(70 * bytes_scanned / total_to_scan)
                        progress_callback(f"Scanning patterns ({self._format_size(bytes_scanned)} / {self._format_size(total_to_scan)})", pct, 100)
                    
                    # Save checkpoint periodically
                    if checkpoint_callback and (bytes_scanned - last_checkpoint_bytes) >= CHECKPOINT_INTERVAL:
                        result.metadata["bytes_scanned"] = bytes_scanned
                        checkpoint_callback(
                            self.get_name(),
                            bytes_scanned,
                            total_to_scan,
                            result.vulnerabilities,
                            result.metadata,
                        )
                        last_checkpoint_bytes = bytes_scanned
        
        # Final metadata update
        result.metadata["bytes_scanned"] = total_to_scan
        result.metadata["scan_complete"] = True
    
    def _scan_chunk_for_patterns(
        self,
        chunk: bytes,
        chunk_offset: int,
        file_path: str,
        result: ScanResult,
        ssti_context: dict,
    ):
        """Scan a single chunk for dangerous patterns.
        
        Args:
            ssti_context: Dict tracking SSTI detection state across chunks:
                - 'reported': Whether SSTI was already reported
        """
        # Check for SSTI exploit patterns (specific patterns, not single keywords)
        if not ssti_context.get('reported', False):
            for pattern in self.JINJA2_SSTI_EXPLOIT_PATTERNS:
                if b".*" in pattern:
                    # Pattern with wildcard - check if both parts appear close together
                    parts = pattern.split(b".*")
                    first_part = parts[0]
                    second_part = parts[1] if len(parts) > 1 else b""
                    
                    idx1 = chunk.find(first_part)
                    while idx1 != -1:
                        search_end = min(idx1 + 500, len(chunk))
                        idx2 = chunk.find(second_part, idx1, search_end)
                        if idx2 != -1:
                            # Found exploit pattern
                            ctx_start = max(0, idx1 - 50)
                            ctx_end = min(len(chunk), idx2 + len(second_part) + 50)
                            context = chunk[ctx_start:ctx_end].decode('utf-8', errors='replace')[:150]
                            
                            vuln = self._create_vulnerability(
                                vulnerability_type="GGUF Exploit Payload - Jinja2 SSTI (targets CVE-2024-25123)",
                                severity=Severity.critical(10.0),
                                description=(
                                    f"File contains RCE exploit payload targeting llama-cpp-python. "
                                    f"Pattern: {first_part.decode(errors='replace')}...{second_part.decode(errors='replace')}"
                                ),
                                location={"file": file_path, "offset": chunk_offset + idx1},
                                evidence={"pattern": pattern.decode(errors='replace'), "context": context, "target_parser": "llama-cpp-python < 0.2.72"},
                                recommendation="DO NOT LOAD with llama-cpp-python < 0.2.72. File contains RCE exploit payload.",
                                references=[
                                    "https://nvd.nist.gov/vuln/detail/CVE-2024-25123",
                                    "https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829",
                                ],
                                cwe_id="CWE-94",
                                cve_id="CVE-2024-25123",
                            )
                            result.add_vulnerability(vuln)
                            ssti_context['reported'] = True
                            return
                        idx1 = chunk.find(first_part, idx1 + 1)
                else:
                    # Direct pattern search
                    if pattern in chunk:
                        offset = chunk.find(pattern)
                        ctx_start = max(0, offset - 50)
                        ctx_end = min(len(chunk), offset + len(pattern) + 50)
                        context = chunk[ctx_start:ctx_end].decode('utf-8', errors='replace')[:150]
                        
                        vuln = self._create_vulnerability(
                            vulnerability_type="GGUF - Jinja2 SSTI Remote Code Execution",
                            severity=Severity.critical(10.0),
                            description=f"CRITICAL: Found SSTI pattern: {pattern.decode(errors='replace')}",
                            location={"file": file_path, "offset": chunk_offset + offset},
                            evidence={"pattern": pattern.decode(errors='replace'), "context": context},
                            recommendation="DO NOT LOAD - Remote Code Execution payload detected.",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2024-25123",
                                "https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829",
                            ],
                            cwe_id="CWE-94",
                            cve_id="CVE-2024-25123",
                        )
                        result.add_vulnerability(vuln)
                        ssti_context['reported'] = True
                        return
        
        # Check for path traversal
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if pattern in chunk:
                offset = chunk.find(pattern)
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Path Traversal in Metadata",
                    severity=Severity.high(8.0),
                    description=f"Path traversal pattern: '{pattern.decode('utf-8', errors='replace')}'",
                    location={"file": file_path, "offset": chunk_offset + offset},
                    evidence={"pattern": pattern.decode('utf-8', errors='replace')},
                    recommendation="Do not load - path traversal attack.",
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                    cwe_id="CWE-22",
                )
                result.add_vulnerability(vuln)
        
        # Check for exploit byte patterns (quick check for critical patterns)
        critical_patterns = [
            (b"\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d", "CVE-2024-21836 n_tensors overflow"),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", "Max uint64 integer overflow"),
        ]
        
        for pattern, description in critical_patterns:
            if pattern in chunk:
                offset = chunk.find(pattern)
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Exploit Pattern Detected",
                    severity=Severity.critical(9.5),
                    description=f"Found exploit pattern: {description}",
                    location={"file": file_path, "offset": chunk_offset + offset},
                    evidence={"pattern_hex": pattern.hex(), "description": description},
                    recommendation="DO NOT LOAD - known exploit pattern.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-21836"],
                    cwe_id="CWE-190",
                )
                result.add_vulnerability(vuln)
    
    def _scan_for_exploit_patterns(self, data: bytes, file_path: str, result: ScanResult):
        """Scan for known exploit byte patterns in the raw file data."""
        # Check for integer overflow patterns
        exploit_bytes_patterns = {
            b"\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d": (
                "CVE-2024-21836 n_tensors overflow pattern",
                "GGUF - Tensor Count Overflow Pattern (CVE-2024-21836)",
            ),
            b"\xff\xff\xff\xff\xff\xff\xff\xff": (
                "Maximum uint64 value - integer overflow",
                "GGUF - Integer Overflow Pattern (max uint64)",
            ),
            b"\xef\xbe\xad\xde": (
                "DEADBEEF exploit marker",
                "GGUF - Exploit Marker (DEADBEEF)",
            ),
            b"\xbe\xba\xfe\xca": (
                "CAFEBABE exploit marker",
                "GGUF - Exploit Marker (CAFEBABE)",
            ),
            b"\x01\x00\x00\x80\x00\x00\x00\x00": (
                "INT32_MAX + 1 signed/unsigned exploit",
                "GGUF - Signed Conversion Exploit (INT32_MAX+1)",
            ),
            b"\xff\x00\x00\x00": (
                "n_dims = 255 - CVE-2024-21802 dimension overflow",
                "GGUF - Dimension Overflow Pattern (CVE-2024-21802)",
            ),
        }
        
        for pattern, (description, vuln_type) in exploit_bytes_patterns.items():
            offset = data.find(pattern)
            if offset != -1:
                # Determine severity based on pattern
                if "CVE" in vuln_type or "Overflow" in vuln_type:
                    severity = Severity.critical(9.5)
                else:
                    severity = Severity.high(8.0)
                
                vuln = self._create_vulnerability(
                    vulnerability_type=vuln_type,
                    severity=severity,
                    description=(
                        f"Found exploit pattern in file: {description}. "
                        f"Pattern: {pattern.hex()} at offset {offset}"
                    ),
                    location={"file": file_path, "offset": offset},
                    evidence={
                        "pattern_hex": pattern.hex(),
                        "offset": offset,
                        "description": description,
                    },
                    recommendation=(
                        "DO NOT LOAD THIS FILE. It contains known exploit patterns "
                        "targeting GGUF parser vulnerabilities."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-21836",
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-21802",
                    ],
                    cwe_id="CWE-190",
                )
                result.add_vulnerability(vuln)
    
    def _scan_for_jinja2_ssti(self, data: bytes, file_path: str, result: ScanResult):
        """Scan for Jinja2 Server-Side Template Injection patterns (RCE).
        
        Uses specific exploit patterns that are unlikely to appear in
        tokenizer vocabulary.
        """
        # Search for specific exploit patterns (these are actual attack patterns,
        # not single words that could be vocabulary tokens)
        for pattern in self.JINJA2_SSTI_EXPLOIT_PATTERNS:
            # For patterns with wildcards, do a simple search for the key parts
            if b".*" in pattern:
                parts = pattern.split(b".*")
                # Check if both parts appear close together (within 500 bytes)
                first_part = parts[0]
                second_part = parts[1] if len(parts) > 1 else b""
                
                idx1 = data.find(first_part)
                while idx1 != -1:
                    # Look for second part within 500 bytes
                    search_end = min(idx1 + 500, len(data))
                    idx2 = data.find(second_part, idx1, search_end)
                    if idx2 != -1:
                        # Found both parts close together - this is likely an exploit
                        offset = idx1
                        context_start = max(0, offset - 50)
                        context_end = min(len(data), idx2 + len(second_part) + 50)
                        context = data[context_start:context_end]
                        display_text = context.decode('utf-8', errors='replace')[:200]
                        
                        vuln = self._create_vulnerability(
                            vulnerability_type="GGUF - Jinja2 SSTI Remote Code Execution",
                            severity=Severity.critical(10.0),
                            description=(
                                f"CRITICAL: Jinja2 SSTI detected! "
                                f"Found exploit pattern: {first_part.decode(errors='replace')}...{second_part.decode(errors='replace')}"
                            ),
                            location={
                                "file": file_path,
                                "offset": offset,
                                "field": "tokenizer.chat_template or metadata",
                            },
                            evidence={
                                "pattern": pattern.decode('utf-8', errors='replace'),
                                "context": display_text,
                                "offset": offset,
                            },
                            recommendation=(
                                "DO NOT LOAD THIS FILE. It contains a Remote Code Execution payload."
                            ),
                            references=[
                                "https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829",
                                "https://nvd.nist.gov/vuln/detail/CVE-2024-25123",
                            ],
                            cwe_id="CWE-94",
                            cve_id="CVE-2024-25123",
                        )
                        result.add_vulnerability(vuln)
                        return
                    # Continue searching for first_part
                    idx1 = data.find(first_part, idx1 + 1)
            else:
                # Direct pattern search (no wildcards)
                if pattern in data:
                    offset = data.find(pattern)
                    context_start = max(0, offset - 50)
                    context_end = min(len(data), offset + len(pattern) + 50)
                    context = data[context_start:context_end]
                    display_text = context.decode('utf-8', errors='replace')[:200]
                    
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Jinja2 SSTI Remote Code Execution",
                        severity=Severity.critical(10.0),
                        description=f"CRITICAL: Jinja2 SSTI detected! Found: {pattern.decode(errors='replace')}",
                        location={
                            "file": file_path,
                            "offset": offset,
                            "field": "tokenizer.chat_template or metadata",
                        },
                        evidence={
                            "pattern": pattern.decode('utf-8', errors='replace'),
                            "context": display_text,
                            "offset": offset,
                        },
                        recommendation="DO NOT LOAD THIS FILE. It contains a Remote Code Execution payload.",
                        references=[
                            "https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829",
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-25123",
                        ],
                        cwe_id="CWE-94",
                        cve_id="CVE-2024-25123",
                    )
                    result.add_vulnerability(vuln)
                    return
    
    def _scan_for_path_traversal(self, data: bytes, file_path: str, result: ScanResult):
        """Scan for path traversal patterns in metadata."""
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if pattern in data:
                # Find the offset
                offset = data.find(pattern)
                context_start = max(0, offset - 20)
                context_end = min(len(data), offset + len(pattern) + 20)
                context = data[context_start:context_end].decode('utf-8', errors='replace')
                
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Path Traversal in Metadata",
                    severity=Severity.high(8.0),
                    description=(
                        f"Path traversal pattern detected in GGUF metadata: "
                        f"'{pattern.decode('utf-8', errors='replace')}'. "
                        f"This could allow reading/writing files outside intended directories."
                    ),
                    location={
                        "file": file_path,
                        "offset": offset,
                    },
                    evidence={
                        "pattern": pattern.decode('utf-8', errors='replace'),
                        "context": context,
                        "offset": offset,
                    },
                    recommendation=(
                        "Do not load this file. It contains path traversal sequences "
                        "that could be exploited for directory traversal attacks."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Path_Traversal",
                    ],
                    cwe_id="CWE-22",
                )
                result.add_vulnerability(vuln)
    
    def _scan_gguf_structure(
        self, f, file_path: str, file_size: int, file_data: bytes, result: ScanResult
    ):
        """Scan GGUF file structure for vulnerabilities."""
        # Read and validate magic (offset 0-3)
        magic = f.read(4)
        
        if magic == self.GGML_MAGIC:
            result.add_warning("Legacy GGML format detected - limited vulnerability checking")
            return
        
        if magic != self.GGUF_MAGIC:
            result.add_error("Not a valid GGUF file - invalid magic bytes")
            return
        
        # Read and validate version (offset 4-7)
        version_bytes = f.read(4)
        version = struct.unpack("<I", version_bytes)[0]
        self._check_version(version, file_path, result)
        
        # Read tensor count (offset 8-15)
        tensor_count_bytes = f.read(8)
        tensor_count = struct.unpack("<Q", tensor_count_bytes)[0]
        self._check_tensor_count(tensor_count, file_path, file_size, result)
        
        # Read metadata KV count (offset 16-23)
        kv_count_bytes = f.read(8)
        kv_count = struct.unpack("<Q", kv_count_bytes)[0]
        self._check_kv_count(kv_count, file_path, result)
        
        # Parse and validate metadata entries (starting at offset 24)
        self._check_metadata_entries(f, file_path, kv_count, file_data, result)
        
        # Parse and validate tensor info
        self._check_tensor_info(f, file_path, tensor_count, file_size, result)
    
    def _check_version(self, version: int, file_path: str, result: ScanResult):
        """Check GGUF version for corruption or manipulation."""
        # Check for known exploit values
        if version in self.EXPLOIT_VALUES:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Version Corruption Exploit",
                severity=Severity.critical(9.0),
                description=(
                    f"GGUF file has corrupted version field containing exploit marker: "
                    f"0x{version:08X} ({self.EXPLOIT_VALUES[version]})"
                ),
                location={"file": file_path, "offset": 4, "field": "version"},
                evidence={
                    "version_value": version,
                    "version_hex": f"0x{version:08X}",
                    "exploit_type": self.EXPLOIT_VALUES[version],
                },
                recommendation=(
                    "This file has been tampered with. Do not load it. "
                    "The version field contains a known exploit pattern."
                ),
                references=[
                    "https://github.com/ggml-org/llama.cpp/security/advisories",
                ],
                cwe_id="CWE-20",
            )
            result.add_vulnerability(vuln)
            return
        
        # Check for invalid version range
        if version < self.GGUF_VERSION_MIN or version > self.GGUF_VERSION_MAX:
            severity = Severity.high(7.5) if version > 1000 else Severity.medium(5.0)
            
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Invalid Version",
                severity=severity,
                description=(
                    f"GGUF file has invalid version: {version} (0x{version:08X}). "
                    f"Valid versions are {self.GGUF_VERSION_MIN}-{self.GGUF_VERSION_MAX}."
                ),
                location={"file": file_path, "offset": 4, "field": "version"},
                evidence={
                    "version": version,
                    "version_hex": f"0x{version:08X}",
                    "valid_range": f"{self.GGUF_VERSION_MIN}-{self.GGUF_VERSION_MAX}",
                },
                recommendation="Verify the file is not corrupted or maliciously crafted.",
                references=[],
                cwe_id="CWE-20",
            )
            result.add_vulnerability(vuln)
    
    def _check_tensor_count(
        self, tensor_count: int, file_path: str, file_size: int, result: ScanResult
    ):
        """Check tensor count for integer overflow exploits (CVE-2024-21836)."""
        # Check for known exploit values
        if tensor_count in self.EXPLOIT_VALUES:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Tensor Count Integer Overflow Exploit (CVE-2024-21836)",
                severity=Severity.critical(9.8),
                description=(
                    f"GGUF file has tensor count set to exploit value: "
                    f"0x{tensor_count:016X} ({self.EXPLOIT_VALUES[tensor_count]}). "
                    "This triggers CVE-2024-21836: allocation of (n_tensors * 88 bytes) "
                    "wraps around causing heap corruption."
                ),
                location={"file": file_path, "offset": 8, "field": "n_tensors"},
                evidence={
                    "tensor_count": tensor_count,
                    "tensor_count_hex": f"0x{tensor_count:016X}",
                    "exploit_type": self.EXPLOIT_VALUES[tensor_count],
                    "overflow_calc": f"{tensor_count} * 88 = {(tensor_count * 88) & 0xFFFFFFFFFFFFFFFF}",
                },
                recommendation=(
                    "DO NOT LOAD THIS FILE. It exploits CVE-2024-21836 to cause "
                    "heap corruption via integer overflow in tensor allocation."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-21836",
                    "https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-8wwf-w4qm-gpqr",
                ],
                cwe_id="CWE-190",
                cve_id="CVE-2024-21836",
            )
            result.add_vulnerability(vuln)
            return
        
        # Check for values that would cause integer overflow when multiplied
        # n_tensors * 88 (struct size) must not overflow
        TENSOR_STRUCT_SIZE = 88
        if tensor_count > self.SIZE_MAX // TENSOR_STRUCT_SIZE:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Tensor Count Integer Overflow (CVE-2024-21836)",
                severity=Severity.critical(9.8),
                description=(
                    f"GGUF tensor count ({tensor_count}) would overflow when multiplied "
                    f"by tensor struct size ({TENSOR_STRUCT_SIZE}). "
                    f"Result: {(tensor_count * TENSOR_STRUCT_SIZE) & 0xFFFFFFFFFFFFFFFF} "
                    "(wrapped around)"
                ),
                location={"file": file_path, "offset": 8, "field": "n_tensors"},
                evidence={
                    "tensor_count": tensor_count,
                    "struct_size": TENSOR_STRUCT_SIZE,
                    "would_allocate": (tensor_count * TENSOR_STRUCT_SIZE) & 0xFFFFFFFFFFFFFFFF,
                },
                recommendation="Do not load - triggers CVE-2024-21836 integer overflow.",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-21836",
                ],
                cwe_id="CWE-190",
                cve_id="CVE-2024-21836",
            )
            result.add_vulnerability(vuln)
            return
        
        # Check for excessive but not overflow values (potential DoS)
        if tensor_count > self.MAX_TENSOR_COUNT:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Excessive Tensor Count (DoS)",
                severity=Severity.high(7.5),
                description=(
                    f"GGUF file claims {tensor_count:,} tensors, exceeding "
                    f"limit ({self.MAX_TENSOR_COUNT:,}). May cause memory exhaustion."
                ),
                location={"file": file_path, "offset": 8, "field": "n_tensors"},
                evidence={
                    "tensor_count": tensor_count,
                    "max_reasonable": self.MAX_TENSOR_COUNT,
                    "file_size": file_size,
                },
                recommendation="Do not load - may cause denial of service.",
                references=[],
                cwe_id="CWE-400",
            )
            result.add_vulnerability(vuln)
        
        # Sanity check: tensor count vs file size
        min_bytes_needed = tensor_count * 20
        if min_bytes_needed > file_size * 100:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Tensor Count/File Size Mismatch",
                severity=Severity.high(7.0),
                description=(
                    f"Claims {tensor_count:,} tensors but file is only {file_size:,} bytes."
                ),
                location={"file": file_path, "offset": 8, "field": "n_tensors"},
                evidence={
                    "tensor_count": tensor_count,
                    "file_size": file_size,
                },
                recommendation="File has been tampered with.",
                references=[],
                cwe_id="CWE-20",
            )
            result.add_vulnerability(vuln)
    
    def _check_kv_count(self, kv_count: int, file_path: str, result: ScanResult):
        """Check metadata key-value count for DoS/overflow exploits."""
        # Check for known exploit values
        if kv_count in self.EXPLOIT_VALUES:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Metadata Count Integer Overflow (DoS)",
                severity=Severity.critical(9.0),
                description=(
                    f"GGUF metadata count set to exploit value: "
                    f"0x{kv_count:016X} ({self.EXPLOIT_VALUES[kv_count]}). "
                    "Causes loader to hang/crash during allocation."
                ),
                location={"file": file_path, "offset": 16, "field": "n_kv"},
                evidence={
                    "kv_count": kv_count,
                    "kv_count_hex": f"0x{kv_count:016X}",
                    "exploit_type": self.EXPLOIT_VALUES[kv_count],
                },
                recommendation="Do not load - causes denial of service.",
                references=[],
                cwe_id="CWE-400",
            )
            result.add_vulnerability(vuln)
            return
        
        if kv_count > self.MAX_KV_COUNT:
            vuln = self._create_vulnerability(
                vulnerability_type="GGUF - Excessive Metadata Count (DoS)",
                severity=Severity.high(7.5),
                description=f"Metadata count {kv_count:,} exceeds limit {self.MAX_KV_COUNT:,}.",
                location={"file": file_path, "offset": 16, "field": "n_kv"},
                evidence={"kv_count": kv_count},
                recommendation="Do not load this file.",
                references=[],
                cwe_id="CWE-400",
            )
            result.add_vulnerability(vuln)
    
    def _check_metadata_entries(
        self, f, file_path: str, kv_count: int, file_data: bytes, result: ScanResult
    ):
        """Parse and validate metadata entries for exploits."""
        entries_to_parse = min(kv_count, 1000)
        
        for i in range(entries_to_parse):
            try:
                current_offset = f.tell()
                
                # Read key string length (8 bytes)
                key_length_bytes = f.read(8)
                if len(key_length_bytes) < 8:
                    break
                
                key_length = struct.unpack("<Q", key_length_bytes)[0]
                
                # Check for signed-to-unsigned exploits (token memcpy vulnerability)
                if key_length in self.SIGNED_UNSIGNED_EXPLOITS:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Signed/Unsigned Conversion Exploit",
                        severity=Severity.critical(9.5),
                        description=(
                            f"Metadata entry {i} has length {key_length} "
                            f"({self.SIGNED_UNSIGNED_EXPLOITS[key_length]}). "
                            "When cast to int32, this becomes negative, bypassing bounds checks "
                            "and causing heap corruption via memcpy."
                        ),
                        location={
                            "file": file_path,
                            "offset": current_offset,
                            "metadata_index": i,
                            "field": "key_length",
                        },
                        evidence={
                            "length": key_length,
                            "as_int32": key_length - 2**32 if key_length > self.INT32_MAX else key_length,
                            "exploit_type": self.SIGNED_UNSIGNED_EXPLOITS[key_length],
                        },
                        recommendation=(
                            "DO NOT LOAD. Exploits signed/unsigned integer conversion vulnerability."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/195.html",
                        ],
                        cwe_id="CWE-195",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Check for known exploit values
                if key_length in self.EXPLOIT_VALUES:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Metadata String Length Exploit",
                        severity=Severity.critical(9.5),
                        description=(
                            f"Metadata entry {i} key length is exploit value: "
                            f"0x{key_length:016X} ({self.EXPLOIT_VALUES[key_length]})"
                        ),
                        location={
                            "file": file_path,
                            "offset": current_offset,
                            "metadata_index": i,
                        },
                        evidence={
                            "key_length": key_length,
                            "key_length_hex": f"0x{key_length:016X}",
                            "exploit_type": self.EXPLOIT_VALUES[key_length],
                        },
                        recommendation="DO NOT LOAD - buffer overflow exploit.",
                        references=[
                            "https://vulners.com/talos/TALOS-2024-1913",
                        ],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Check for excessive string length
                if key_length > self.MAX_STRING_LENGTH:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Excessive Metadata Key Length",
                        severity=Severity.high(8.0),
                        description=f"Metadata entry {i} key length: {key_length:,} bytes",
                        location={
                            "file": file_path,
                            "offset": current_offset,
                            "metadata_index": i,
                        },
                        evidence={"key_length": key_length},
                        recommendation="Potential buffer overflow/DoS.",
                        references=[],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Read the key
                if key_length > 0 and key_length < 10000:
                    key_data = f.read(key_length)
                    
                    # Check for dangerous keys
                    for dangerous_key in self.DANGEROUS_METADATA_KEYS:
                        if dangerous_key in key_data:
                            # This key can contain exploitable content
                            # We already scanned for SSTI patterns above
                            pass
                else:
                    f.seek(min(key_length, self.MAX_STRING_LENGTH), 1)
                
                # Read value type (4 bytes)
                value_type_bytes = f.read(4)
                if len(value_type_bytes) < 4:
                    break
                
                value_type = struct.unpack("<I", value_type_bytes)[0]
                
                # Check for invalid type
                if value_type not in self.GGUF_TYPE_SIZES:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Invalid Metadata Type",
                        severity=Severity.medium(6.0),
                        description=f"Metadata entry {i} has invalid type: {value_type}",
                        location={"file": file_path, "metadata_index": i},
                        evidence={"value_type": value_type},
                        recommendation="File may be corrupted or malicious.",
                        references=[],
                        cwe_id="CWE-20",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Check value for exploits
                self._check_metadata_value(f, file_path, i, value_type, result)
                
            except struct.error:
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Truncated Metadata",
                    severity=Severity.medium(5.5),
                    description=f"File ended unexpectedly at metadata entry {i}",
                    location={"file": file_path, "metadata_index": i},
                    evidence={},
                    recommendation="File is truncated or corrupted.",
                    references=[],
                    cwe_id="CWE-20",
                )
                result.add_vulnerability(vuln)
                break
    
    def _check_metadata_value(
        self, f, file_path: str, entry_index: int, value_type: int, result: ScanResult
    ):
        """Check metadata value for exploits."""
        type_size = self.GGUF_TYPE_SIZES.get(value_type, 0)
        
        if type_size > 0:
            f.read(type_size)
        
        elif value_type == 8:  # String
            current_offset = f.tell()
            length_bytes = f.read(8)
            if len(length_bytes) < 8:
                return
            
            length = struct.unpack("<Q", length_bytes)[0]
            
            # Check for signed/unsigned exploits
            if length in self.SIGNED_UNSIGNED_EXPLOITS:
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Token Length Signed Conversion Exploit",
                    severity=Severity.critical(9.5),
                    description=(
                        f"String value length {length} exploits signed/unsigned conversion. "
                        f"{self.SIGNED_UNSIGNED_EXPLOITS[length]}"
                    ),
                    location={
                        "file": file_path,
                        "offset": current_offset,
                        "metadata_index": entry_index,
                    },
                    evidence={
                        "length": length,
                        "as_signed": length - 2**32 if length > self.INT32_MAX else length,
                    },
                    recommendation="DO NOT LOAD - memcpy heap overflow exploit.",
                    references=[],
                    cwe_id="CWE-195",
                )
                result.add_vulnerability(vuln)
                return
            
            # Check for exploit values
            if length in self.EXPLOIT_VALUES:
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Metadata String Value Length Exploit",
                    severity=Severity.critical(9.0),
                    description=f"String value at entry {entry_index} has exploit length: 0x{length:016X}",
                    location={"file": file_path, "offset": current_offset, "metadata_index": entry_index},
                    evidence={
                        "string_length": length,
                        "exploit_type": self.EXPLOIT_VALUES[length],
                    },
                    recommendation="Do not load - buffer overflow.",
                    references=[],
                    cwe_id="CWE-120",
                )
                result.add_vulnerability(vuln)
                return
            
            # Skip string
            skip_length = min(length, self.MAX_STRING_LENGTH)
            f.read(skip_length)
        
        elif value_type == 9:  # Array
            current_offset = f.tell()
            
            array_type_bytes = f.read(4)
            if len(array_type_bytes) < 4:
                return
            array_type = struct.unpack("<I", array_type_bytes)[0]
            
            array_len_bytes = f.read(8)
            if len(array_len_bytes) < 8:
                return
            array_len = struct.unpack("<Q", array_len_bytes)[0]
            
            # Check for exploit values
            if array_len in self.EXPLOIT_VALUES or array_len in self.SIGNED_UNSIGNED_EXPLOITS:
                exploit_type = self.EXPLOIT_VALUES.get(
                    array_len, self.SIGNED_UNSIGNED_EXPLOITS.get(array_len, "Unknown")
                )
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Metadata Array Length Exploit",
                    severity=Severity.critical(9.0),
                    description=f"Array length at entry {entry_index}: 0x{array_len:016X} ({exploit_type})",
                    location={"file": file_path, "offset": current_offset, "metadata_index": entry_index},
                    evidence={
                        "array_length": array_len,
                        "array_type": self.GGUF_TYPE_NAMES.get(array_type, array_type),
                    },
                    recommendation="Do not load - integer overflow.",
                    references=[],
                    cwe_id="CWE-190",
                )
                result.add_vulnerability(vuln)
                return
            
            if array_len > self.MAX_ARRAY_LENGTH:
                vuln = self._create_vulnerability(
                    vulnerability_type="GGUF - Excessive Array Length",
                    severity=Severity.high(7.5),
                    description=f"Array at entry {entry_index} has {array_len:,} elements",
                    location={"file": file_path, "metadata_index": entry_index},
                    evidence={"array_length": array_len},
                    recommendation="Potential memory exhaustion.",
                    references=[],
                    cwe_id="CWE-400",
                )
                result.add_vulnerability(vuln)
                return
            
            # Skip array
            elem_size = self.GGUF_TYPE_SIZES.get(array_type, 0)
            if elem_size > 0:
                skip_len = min(array_len, self.MAX_ARRAY_LENGTH)
                f.read(elem_size * skip_len)
    
    def _check_tensor_info(
        self, f, file_path: str, tensor_count: int, file_size: int, result: ScanResult
    ):
        """Check tensor information for CVE-2024-21802 and other overflows."""
        tensors_to_parse = min(tensor_count, 1000)
        cumulative_size = 0
        
        for i in range(tensors_to_parse):
            try:
                current_offset = f.tell()
                
                # Read tensor name length
                name_length_bytes = f.read(8)
                if len(name_length_bytes) < 8:
                    break
                
                name_length = struct.unpack("<Q", name_length_bytes)[0]
                
                # Check for exploit values
                if name_length in self.EXPLOIT_VALUES or name_length in self.SIGNED_UNSIGNED_EXPLOITS:
                    exploit_info = self.EXPLOIT_VALUES.get(
                        name_length, self.SIGNED_UNSIGNED_EXPLOITS.get(name_length, "")
                    )
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Tensor Name Length Exploit",
                        severity=Severity.critical(9.0),
                        description=f"Tensor {i} name length: 0x{name_length:016X} ({exploit_info})",
                        location={"file": file_path, "offset": current_offset, "tensor_index": i},
                        evidence={"name_length": name_length},
                        recommendation="Do not load - buffer overflow.",
                        references=[],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                if name_length > self.MAX_STRING_LENGTH:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Excessive Tensor Name Length",
                        severity=Severity.high(7.5),
                        description=f"Tensor {i} name length: {name_length:,} bytes",
                        location={"file": file_path, "tensor_index": i},
                        evidence={"name_length": name_length},
                        recommendation="Potential buffer overflow.",
                        references=[],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Skip name
                f.read(min(name_length, self.MAX_STRING_LENGTH))
                
                # Read n_dims (4 bytes)
                n_dims_bytes = f.read(4)
                if len(n_dims_bytes) < 4:
                    break
                
                n_dims = struct.unpack("<I", n_dims_bytes)[0]
                
                # CVE-2024-21802: n_dims > GGML_MAX_DIMS causes heap buffer overflow
                if n_dims > self.GGML_MAX_DIMS:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Tensor Dimension Overflow (CVE-2024-21802)",
                        severity=Severity.critical(9.0),
                        description=(
                            f"Tensor {i} has {n_dims} dimensions, exceeding GGML_MAX_DIMS ({self.GGML_MAX_DIMS}). "
                            "This triggers CVE-2024-21802: heap-based buffer overflow when loading tensor dimensions."
                        ),
                        location={"file": file_path, "offset": current_offset, "tensor_index": i},
                        evidence={
                            "n_dims": n_dims,
                            "max_dims": self.GGML_MAX_DIMS,
                            "overflow_bytes": (n_dims - self.GGML_MAX_DIMS) * 8,
                        },
                        recommendation=(
                            "DO NOT LOAD. Exploits CVE-2024-21802 to overflow heap buffer "
                            "during dimension array read."
                        ),
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-21802",
                            "https://github.com/ggml-org/llama.cpp/security/advisories",
                        ],
                        cwe_id="CWE-122",
                        cve_id="CVE-2024-21802",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                # Read dimensions and check for overflow
                tensor_size = 1
                dimensions = []
                
                for d in range(min(n_dims, 16)):
                    dim_bytes = f.read(8)
                    if len(dim_bytes) < 8:
                        break
                    
                    dim = struct.unpack("<Q", dim_bytes)[0]
                    dimensions.append(dim)
                    
                    # Check for exploit values
                    if dim in self.EXPLOIT_VALUES:
                        vuln = self._create_vulnerability(
                            vulnerability_type="GGUF - Tensor Dimension Exploit Value",
                            severity=Severity.critical(9.0),
                            description=f"Tensor {i} dimension {d}: 0x{dim:016X}",
                            location={"file": file_path, "tensor_index": i},
                            evidence={"dimension": dim, "exploit_type": self.EXPLOIT_VALUES[dim]},
                            recommendation="Integer overflow exploit.",
                            references=[],
                            cwe_id="CWE-190",
                        )
                        result.add_vulnerability(vuln)
                        return
                    
                    # Check for integer overflow
                    if dim > 0 and tensor_size > self.SIZE_MAX // dim:
                        vuln = self._create_vulnerability(
                            vulnerability_type="GGUF - Integer Overflow in Tensor Size",
                            severity=Severity.critical(9.0),
                            description=f"Tensor {i} dimension calculation overflows",
                            location={"file": file_path, "tensor_index": i},
                            evidence={"dimension": dim, "current_size": tensor_size, "dimensions": dimensions},
                            recommendation="Known attack vector (CVE-2025-53630).",
                            references=[
                                "https://cvefeed.io/vuln/detail/CVE-2025-53630",
                            ],
                            cwe_id="CWE-190",
                            cve_id="CVE-2025-53630",
                        )
                        result.add_vulnerability(vuln)
                        return
                    
                    tensor_size *= dim if dim > 0 else 1
                
                # Check cumulative overflow
                if cumulative_size > self.SIZE_MAX - tensor_size:
                    vuln = self._create_vulnerability(
                        vulnerability_type="GGUF - Cumulative Size Integer Overflow",
                        severity=Severity.critical(9.0),
                        description="Cumulative tensor sizes overflow",
                        location={"file": file_path, "tensor_index": i},
                        evidence={"cumulative_size": cumulative_size, "tensor_size": tensor_size},
                        recommendation="Known attack vector.",
                        references=[],
                        cwe_id="CWE-190",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                cumulative_size += tensor_size
                
                # Skip type and offset
                f.read(8)
                
            except struct.error:
                break
