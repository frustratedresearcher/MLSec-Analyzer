"""Metadata and header exploitation scanner."""

import json
import os
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class MetadataScanner(BaseScanner):
    """Scanner for metadata and header exploitation vulnerabilities.
    
    Detects potential buffer overflow, format string, and embedded
    script vulnerabilities in model metadata sections.
    """
    
    # Format string patterns that could be exploited
    FORMAT_STRING_PATTERNS = [
        re.compile(rb'%n'),      # Write to memory
        re.compile(rb'%s'),      # Could cause crash/leak
        re.compile(rb'%x'),      # Hex dump
        re.compile(rb'%p'),      # Pointer leak
        re.compile(rb'%\d+\$'),  # Positional format
    ]
    
    # Script/code patterns in metadata
    SCRIPT_PATTERNS = [
        (re.compile(rb'<script', re.IGNORECASE), "HTML script tag"),
        (re.compile(rb'javascript:', re.IGNORECASE), "JavaScript protocol"),
        (re.compile(rb'vbscript:', re.IGNORECASE), "VBScript protocol"),
        (re.compile(rb'data:text/html', re.IGNORECASE), "Data URL with HTML"),
        (re.compile(rb'eval\s*\(', re.IGNORECASE), "eval() call"),
        (re.compile(rb'exec\s*\(', re.IGNORECASE), "exec() call"),
        (re.compile(rb'__import__\s*\(', re.IGNORECASE), "__import__() call"),
        (re.compile(rb'os\.system\s*\(', re.IGNORECASE), "os.system() call"),
        (re.compile(rb'subprocess\s*\.\s*\w+\s*\(', re.IGNORECASE), "subprocess call"),
    ]
    
    # Reasonable limits for metadata fields
    MAX_STRING_LENGTH = 100000  # 100KB
    MAX_DESCRIPTION_LENGTH = 1000000  # 1MB
    
    def get_name(self) -> str:
        return "Metadata Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return ["*"]  # Scan all formats
    
    def get_description(self) -> str:
        return "Detects buffer overflow and injection vulnerabilities in model metadata"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a model file for metadata vulnerabilities."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        ext = os.path.splitext(model_path)[1].lower()
        
        # Dispatch to appropriate scanner based on format
        if ext in [".h5", ".hdf5"]:
            self._scan_hdf5_metadata(model_path, result)
        elif ext in [".keras"]:
            self._scan_keras_metadata(model_path, result)
        elif ext in [".onnx"]:
            self._scan_onnx_metadata(model_path, result)
        elif ext in [".safetensors"]:
            self._scan_safetensors_metadata(model_path, result)
        
        # Always do generic metadata scan
        self._scan_generic_metadata(model_path, result)
        
        return result
    
    def _scan_hdf5_metadata(self, file_path: str, result: ScanResult):
        """Scan HDF5 file metadata."""
        try:
            import h5py
        except ImportError:
            return
        
        try:
            with h5py.File(file_path, "r") as f:
                self._scan_h5_attrs_recursive(f, file_path, result)
        except Exception as e:
            result.add_warning(f"Failed to scan HDF5 metadata: {e}")
    
    def _scan_h5_attrs_recursive(self, group, file_path: str, result: ScanResult, path: str = ""):
        """Recursively scan HDF5 attributes."""
        # Check group attributes
        for attr_name in group.attrs.keys():
            attr_value = group.attrs[attr_name]
            self._check_metadata_value(
                attr_name, attr_value,
                f"{file_path}:{path}/{attr_name}",
                result
            )
        
        # Recurse into subgroups
        if hasattr(group, "keys"):
            for key in group.keys():
                item = group[key]
                current_path = f"{path}/{key}" if path else key
                
                if hasattr(item, "attrs"):
                    for attr_name in item.attrs.keys():
                        attr_value = item.attrs[attr_name]
                        self._check_metadata_value(
                            attr_name, attr_value,
                            f"{file_path}:{current_path}/{attr_name}",
                            result
                        )
                
                if hasattr(item, "keys"):
                    self._scan_h5_attrs_recursive(item, file_path, result, current_path)
    
    def _scan_keras_metadata(self, file_path: str, result: ScanResult):
        """Scan Keras model metadata."""
        try:
            if not zipfile.is_zipfile(file_path):
                return
            
            with zipfile.ZipFile(file_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".json"):
                        try:
                            content = zf.read(name).decode("utf-8")
                            self._check_json_metadata(
                                content,
                                f"{file_path}:{name}",
                                result
                            )
                        except Exception:
                            continue
        except Exception as e:
            result.add_warning(f"Failed to scan Keras metadata: {e}")
    
    def _scan_onnx_metadata(self, file_path: str, result: ScanResult):
        """Scan ONNX model metadata."""
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            
            # ONNX files are protobuf - look for metadata strings
            self._check_binary_metadata(content, file_path, result)
            
        except Exception as e:
            result.add_warning(f"Failed to scan ONNX metadata: {e}")
    
    def _scan_safetensors_metadata(self, file_path: str, result: ScanResult):
        """Scan SafeTensors metadata header."""
        try:
            with open(file_path, "rb") as f:
                # SafeTensors header is JSON at the start
                header_size = struct.unpack("<Q", f.read(8))[0]
                
                # Check for excessive header size
                if header_size > 100 * 1024 * 1024:  # 100MB
                    vuln = self._create_vulnerability(
                        vulnerability_type="Metadata - Excessive Header Size",
                        severity=Severity.medium(5.0),
                        description=(
                            f"SafeTensors header is {header_size} bytes, which is "
                            f"unusually large and may indicate malicious content."
                        ),
                        location={"file": file_path},
                        evidence={"header_size": header_size},
                        recommendation="Review the file before loading.",
                        references=[],
                        cwe_id="CWE-400",
                    )
                    result.add_vulnerability(vuln)
                    return
                
                header_bytes = f.read(min(header_size, 10 * 1024 * 1024))
                
                try:
                    header_str = header_bytes.decode("utf-8")
                    self._check_json_metadata(header_str, file_path, result)
                except UnicodeDecodeError:
                    pass
                    
        except Exception as e:
            result.add_warning(f"Failed to scan SafeTensors metadata: {e}")
    
    def _scan_generic_metadata(self, file_path: str, result: ScanResult):
        """Generic scan for metadata issues."""
        try:
            with open(file_path, "rb") as f:
                # Read first 1MB for metadata
                content = f.read(1024 * 1024)
        except IOError:
            return
        
        self._check_binary_metadata(content, file_path, result)
    
    def _check_metadata_value(
        self,
        name: str,
        value: Any,
        location: str,
        result: ScanResult
    ):
        """Check a single metadata value for issues."""
        # Convert to bytes for pattern matching
        if isinstance(value, bytes):
            value_bytes = value
        elif isinstance(value, str):
            value_bytes = value.encode("utf-8", errors="replace")
        else:
            value_bytes = str(value).encode("utf-8", errors="replace")
        
        # Check length
        if len(value_bytes) > self.MAX_STRING_LENGTH:
            vuln = self._create_vulnerability(
                vulnerability_type="Metadata - Excessive Length",
                severity=Severity.medium(5.5),
                description=(
                    f"Metadata field '{name}' has length {len(value_bytes)}, "
                    f"which could cause buffer overflow in parsers."
                ),
                location={"file": location},
                evidence={
                    "field": name,
                    "length": len(value_bytes),
                    "max_expected": self.MAX_STRING_LENGTH,
                },
                recommendation=(
                    "Verify the metadata is not crafted to exploit buffer vulnerabilities."
                ),
                references=[],
                cwe_id="CWE-120",
            )
            result.add_vulnerability(vuln)
        
        # Check for format strings
        for pattern in self.FORMAT_STRING_PATTERNS:
            if pattern.search(value_bytes):
                vuln = self._create_vulnerability(
                    vulnerability_type="Metadata - Format String",
                    severity=Severity.medium(6.0),
                    description=(
                        f"Metadata field '{name}' contains format string patterns "
                        f"that could exploit printf-style vulnerabilities."
                    ),
                    location={"file": location},
                    evidence={
                        "field": name,
                        "pattern": pattern.pattern.decode(),
                    },
                    recommendation=(
                        "Review the metadata for potential format string exploits."
                    ),
                    references=[],
                    cwe_id="CWE-134",
                )
                result.add_vulnerability(vuln)
                break
        
        # Check for embedded scripts
        for pattern, description in self.SCRIPT_PATTERNS:
            if pattern.search(value_bytes):
                vuln = self._create_vulnerability(
                    vulnerability_type="Metadata - Embedded Script",
                    severity=Severity.high(7.0),
                    description=(
                        f"Metadata field '{name}' contains {description}, "
                        f"which could execute when displayed or processed."
                    ),
                    location={"file": location},
                    evidence={
                        "field": name,
                        "script_type": description,
                        "preview": value_bytes[:200].decode("utf-8", errors="replace"),
                    },
                    recommendation=(
                        "Do not display this metadata in web interfaces without sanitization."
                    ),
                    references=[],
                    cwe_id="CWE-79",
                )
                result.add_vulnerability(vuln)
                break
    
    def _check_json_metadata(self, content: str, location: str, result: ScanResult):
        """Check JSON metadata for issues."""
        try:
            data = json.loads(content)
            self._check_json_recursive(data, location, result, "")
        except json.JSONDecodeError:
            pass
    
    def _check_json_recursive(
        self,
        data: Any,
        location: str,
        result: ScanResult,
        path: str
    ):
        """Recursively check JSON data."""
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                
                if isinstance(value, str):
                    self._check_metadata_value(key, value, location, result)
                else:
                    self._check_json_recursive(value, location, result, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._check_json_recursive(item, location, result, f"{path}[{i}]")
    
    def _check_binary_metadata(self, content: bytes, location: str, result: ScanResult):
        """Check binary content for metadata issues."""
        # Look for very long sequences without null bytes (potential overflow strings)
        # Split by null bytes and check segment lengths
        segments = content.split(b"\x00")
        
        for i, segment in enumerate(segments):
            if len(segment) > self.MAX_STRING_LENGTH:
                # Check if it looks like text
                printable = sum(1 for b in segment if 32 <= b <= 126)
                if printable / len(segment) > 0.7:  # Mostly printable
                    vuln = self._create_vulnerability(
                        vulnerability_type="Metadata - Long Text Segment",
                        severity=Severity.low(3.5),
                        description=(
                            f"Binary content contains a {len(segment)}-byte text segment "
                            f"that could cause issues in some parsers."
                        ),
                        location={"file": location, "segment_index": i},
                        evidence={
                            "length": len(segment),
                            "preview": segment[:100].decode("utf-8", errors="replace"),
                        },
                        recommendation="Review long text segments for potential exploits.",
                        references=[],
                        cwe_id="CWE-120",
                    )
                    result.add_vulnerability(vuln)
                    break
        
        # Check for embedded scripts in binary
        for pattern, description in self.SCRIPT_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                vuln = self._create_vulnerability(
                    vulnerability_type="Metadata - Embedded Code Pattern",
                    severity=Severity.medium(5.0),
                    description=(
                        f"Binary content contains {description} patterns "
                        f"that may indicate embedded malicious code."
                    ),
                    location={"file": location},
                    evidence={
                        "pattern_type": description,
                        "count": len(matches),
                    },
                    recommendation="Review the file for embedded code.",
                    references=[],
                    cwe_id="CWE-94",
                )
                result.add_vulnerability(vuln)
                break
