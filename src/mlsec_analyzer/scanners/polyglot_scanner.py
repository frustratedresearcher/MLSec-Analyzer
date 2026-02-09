"""Polyglot file attack scanner with Fickling integration."""

import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability

# Try to import fickling for PyTorch polyglot detection
try:
    from fickling.pytorch import PyTorchModelWrapper
    FICKLING_PYTORCH_AVAILABLE = True
except ImportError:
    FICKLING_PYTORCH_AVAILABLE = False


class PolyglotScanner(BaseScanner):
    """Scanner for polyglot file attacks.
    
    Detects files that are valid in multiple formats simultaneously,
    which can be used to bypass security filters.
    
    Uses Fickling (https://github.com/trailofbits/fickling) for advanced
    PyTorch polyglot detection when available.
    """
    
    # Magic byte signatures for various formats
    FORMAT_SIGNATURES = {
        # Images
        "jpeg": [b"\xff\xd8\xff"],
        "png": [b"\x89PNG\r\n\x1a\n"],
        "gif": [b"GIF87a", b"GIF89a"],
        "bmp": [b"BM"],
        "webp": [b"RIFF"],
        "ico": [b"\x00\x00\x01\x00"],
        
        # Archives
        "zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
        "rar": [b"Rar!\x1a\x07"],
        "gzip": [b"\x1f\x8b"],
        "bzip2": [b"BZh"],
        "7z": [b"7z\xbc\xaf\x27\x1c"],
        
        # Documents
        "pdf": [b"%PDF"],
        "rtf": [b"{\\rtf"],
        
        # Executables
        "exe_mz": [b"MZ"],
        "elf": [b"\x7fELF"],
        "macho": [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", 
                  b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"],
        
        # Scripts
        "shell": [b"#!/"],
        
        # ML Formats
        "pickle": [b"\x80\x04\x95", b"\x80\x03", b"\x80\x02"],
        "hdf5": [b"\x89HDF\r\n\x1a\n"],
        "gguf": [b"GGUF"],
        "onnx": [],
        
        # Others
        "sqlite": [b"SQLite format 3\x00"],
    }
    
    # PyTorch format signatures (used by Fickling)
    PYTORCH_FORMATS = {
        "PyTorch v0.1.1": "Tar file with sys_info, pickle, storages, and tensors",
        "PyTorch v0.1.10": "Stacked pickle files",
        "TorchScript v1.0": "ZIP file with model.json",
        "TorchScript v1.1": "ZIP file with model.json and attributes.pkl",
        "TorchScript v1.3": "ZIP file with data.pkl and constants.pkl",
        "TorchScript v1.4": "ZIP file with data.pkl, constants.pkl, and version >= 2",
        "PyTorch v1.3": "ZIP file containing data.pkl",
        "PyTorch model archive format": "ZIP with Python code and pickle files",
    }
    
    NON_MODEL_FORMATS = {"jpeg", "png", "gif", "bmp", "webp", "ico", "pdf", "rtf"}
    HIDING_FORMATS = {"zip", "jpeg", "png", "gif", "pdf"}
    
    def get_name(self) -> str:
        return "Polyglot Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return ["*"]
    
    def get_description(self) -> str:
        desc = "Detects polyglot files that are valid in multiple formats"
        if FICKLING_PYTORCH_AVAILABLE:
            desc += " (with Fickling PyTorch polyglot detection)"
        return desc
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan a file for polyglot characteristics."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        if os.path.isdir(model_path):
            return result
        
        # Use Fickling for PyTorch polyglot detection if available
        ext = os.path.splitext(model_path)[1].lower()
        if FICKLING_PYTORCH_AVAILABLE and ext in [".pth", ".pt", ".bin"]:
            self._analyze_pytorch_polyglot(model_path, result)
        
        # Standard polyglot detection
        try:
            with open(model_path, "rb") as f:
                header = f.read(32)
                
                file_size = os.path.getsize(model_path)
                if file_size > 1024:
                    f.seek(-1024, 2)
                    tail = f.read(1024)
                else:
                    f.seek(0)
                    tail = f.read()
                
                f.seek(0)
                full_header = f.read(min(file_size, 64 * 1024))
                
        except IOError as e:
            result.add_error(f"Failed to read file: {e}")
            return result
        
        # Detect formats in header
        header_formats = self._detect_formats(header)
        
        # Check file extension
        claimed_format = self._extension_to_format(ext)
        
        # Check for format mismatch
        if claimed_format and header_formats:
            if claimed_format not in header_formats:
                detected_str = ", ".join(header_formats)
                vuln = self._create_vulnerability(
                    vulnerability_type="Polyglot - Format Mismatch",
                    severity=Severity.medium(6.0),
                    description=(
                        f"File extension '{ext}' claims format '{claimed_format}' but "
                        f"magic bytes indicate: {detected_str}"
                    ),
                    location={"file": model_path},
                    evidence={
                        "extension": ext,
                        "claimed_format": claimed_format,
                        "detected_formats": list(header_formats),
                        "magic_bytes": header[:16].hex(),
                    },
                    recommendation="Verify the file format matches its extension.",
                    references=[
                        "https://github.com/trailofbits/fickling",
                    ],
                    cwe_id="CWE-434",
                )
                result.add_vulnerability(vuln)
        
        # Check for multiple format signatures
        if len(header_formats) > 1:
            vuln = self._create_vulnerability(
                vulnerability_type="Polyglot - Multiple Format Signatures",
                severity=Severity.medium(5.5),
                description=f"File matches multiple format signatures: {', '.join(header_formats)}",
                location={"file": model_path},
                evidence={"detected_formats": list(header_formats)},
                recommendation="This file may be a polyglot. Verify its intended format.",
                references=[],
                cwe_id="CWE-434",
            )
            result.add_vulnerability(vuln)
        
        # Check for embedded formats
        embedded = self._find_embedded_formats(full_header, tail, header_formats)
        
        if embedded:
            for embed_format, offset, context in embedded:
                if embed_format in ["pickle", "exe_mz", "elf", "shell"]:
                    severity = Severity.high(7.5)
                    description = (
                        f"File contains embedded {embed_format} data at offset {offset}. "
                        f"This is highly suspicious and could execute malicious code."
                    )
                else:
                    severity = Severity.medium(5.0)
                    description = f"File contains embedded {embed_format} data at offset {offset}."
                
                vuln = self._create_vulnerability(
                    vulnerability_type="Polyglot - Embedded Format",
                    severity=severity,
                    description=description,
                    location={"file": model_path, "offset": offset},
                    evidence={
                        "primary_format": list(header_formats)[0] if header_formats else "unknown",
                        "embedded_format": embed_format,
                        "offset": offset,
                        "context": context,
                    },
                    recommendation="This file appears to contain hidden data.",
                    references=["https://github.com/trailofbits/fickling"],
                    cwe_id="CWE-434",
                )
                result.add_vulnerability(vuln)
        
        # Check for trailing data
        trailing = self._check_trailing_data(model_path, header_formats)
        
        if trailing:
            trail_format, trail_size = trailing
            if trail_format:
                severity = Severity.high(7.0) if trail_format in ["pickle", "exe_mz", "zip"] else Severity.medium(5.5)
                vuln = self._create_vulnerability(
                    vulnerability_type="Polyglot - Trailing Data",
                    severity=severity,
                    description=(
                        f"File has {trail_size} bytes of trailing data that appears to be "
                        f"'{trail_format}' format. This may hide malicious content."
                    ),
                    location={"file": model_path},
                    evidence={"trailing_format": trail_format, "trailing_size": trail_size},
                    recommendation="Trailing data may contain hidden malicious code.",
                    references=[],
                    cwe_id="CWE-434",
                )
                result.add_vulnerability(vuln)
        
        return result
    
    def _analyze_pytorch_polyglot(self, file_path: str, result: ScanResult):
        """Use Fickling to analyze PyTorch file for polyglot characteristics."""
        try:
            wrapper = PyTorchModelWrapper(file_path)
            formats = wrapper.formats
            
            # Store format info
            result.metadata["pytorch_formats"] = formats
            result.metadata["likely_format"] = wrapper.likely_format if hasattr(wrapper, 'likely_format') else None
            
            # Check if file matches multiple PyTorch formats (unusual)
            if len(formats) > 1:
                vuln = self._create_vulnerability(
                    vulnerability_type="Polyglot - Multiple PyTorch Formats (Fickling)",
                    severity=Severity.high(7.0),
                    description=(
                        f"Fickling detected file is valid as multiple PyTorch formats: "
                        f"{', '.join(formats)}. This is unusual and may indicate a polyglot attack."
                    ),
                    location={"file": file_path},
                    evidence={
                        "pytorch_formats": formats,
                        "format_descriptions": {
                            f: self.PYTORCH_FORMATS.get(f, "Unknown") 
                            for f in formats
                        },
                    },
                    recommendation=(
                        "Review this file carefully. Multiple valid format interpretations "
                        "may be used to bypass security controls."
                    ),
                    references=[
                        "https://github.com/trailofbits/fickling",
                        "https://blog.trailofbits.com/2021/03/15/never-a-dull-moment-when-you-are-pickling/",
                    ],
                    cwe_id="CWE-434",
                )
                result.add_vulnerability(vuln)
            
            # Check for legacy/unusual formats
            legacy_formats = ["PyTorch v0.1.1", "PyTorch v0.1.10"]
            for fmt in formats:
                if fmt in legacy_formats:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Polyglot - Legacy PyTorch Format (Fickling)",
                        severity=Severity.medium(5.0),
                        description=(
                            f"File uses legacy PyTorch format '{fmt}' which may have "
                            f"different security characteristics than modern formats."
                        ),
                        location={"file": file_path},
                        evidence={"format": fmt},
                        recommendation="Consider converting to modern PyTorch format.",
                        references=["https://github.com/trailofbits/fickling"],
                        cwe_id="CWE-434",
                    )
                    result.add_vulnerability(vuln)
                    
        except Exception as e:
            result.add_warning(f"Fickling PyTorch analysis failed: {e}")
    
    def _detect_formats(self, data: bytes) -> Set[str]:
        """Detect formats based on magic bytes."""
        detected = set()
        for format_name, signatures in self.FORMAT_SIGNATURES.items():
            for sig in signatures:
                if data.startswith(sig):
                    detected.add(format_name)
                    break
        return detected
    
    def _extension_to_format(self, ext: str) -> Optional[str]:
        """Map file extension to format name."""
        mapping = {
            ".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif",
            ".bmp": "bmp", ".webp": "webp", ".ico": "ico",
            ".zip": "zip", ".rar": "rar", ".gz": "gzip", ".bz2": "bzip2", ".7z": "7z",
            ".pdf": "pdf", ".rtf": "rtf",
            ".exe": "exe_mz", ".dll": "exe_mz",
            ".pkl": "pickle", ".pickle": "pickle",
            ".pth": "zip", ".pt": "zip",
            ".h5": "hdf5", ".hdf5": "hdf5",
            ".keras": "zip", ".gguf": "gguf", ".onnx": "onnx",
        }
        return mapping.get(ext.lower())
    
    def _find_embedded_formats(
        self, data: bytes, tail: bytes, primary_formats: Set[str]
    ) -> List[Tuple[str, int, str]]:
        """Find embedded format signatures within the data."""
        embedded = []
        search_start = 64
        
        for format_name, signatures in self.FORMAT_SIGNATURES.items():
            if format_name in primary_formats:
                continue
            for sig in signatures:
                offset = data.find(sig, search_start)
                if offset != -1:
                    context = data[offset:offset+32].hex()
                    embedded.append((format_name, offset, context))
                    break
                tail_offset = tail.find(sig)
                if tail_offset != -1:
                    context = tail[tail_offset:tail_offset+32].hex()
                    embedded.append((format_name, f"tail+{tail_offset}", context))
                    break
        return embedded
    
    def _check_trailing_data(
        self, file_path: str, header_formats: Set[str]
    ) -> Optional[Tuple[str, int]]:
        """Check for trailing data after the expected end of the primary format."""
        if "jpeg" in header_formats:
            return self._check_jpeg_trailing(file_path)
        elif "png" in header_formats:
            return self._check_png_trailing(file_path)
        elif "gif" in header_formats:
            return self._check_gif_trailing(file_path)
        return None
    
    def _check_jpeg_trailing(self, file_path: str) -> Optional[Tuple[str, int]]:
        """Check for data after JPEG EOI marker."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            eoi_offset = data.rfind(b"\xff\xd9")
            if eoi_offset != -1 and eoi_offset + 2 < len(data):
                trailing = data[eoi_offset + 2:]
                trailing_size = len(trailing)
                if trailing_size > 10:
                    formats = self._detect_formats(trailing)
                    if formats:
                        return (list(formats)[0], trailing_size)
                    return ("unknown", trailing_size)
        except Exception:
            pass
        return None
    
    def _check_png_trailing(self, file_path: str) -> Optional[Tuple[str, int]]:
        """Check for data after PNG IEND chunk."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            iend_offset = data.find(b"IEND")
            if iend_offset != -1:
                expected_end = iend_offset + 8
                if expected_end < len(data):
                    trailing = data[expected_end:]
                    trailing_size = len(trailing)
                    if trailing_size > 10:
                        formats = self._detect_formats(trailing)
                        if formats:
                            return (list(formats)[0], trailing_size)
                        return ("unknown", trailing_size)
        except Exception:
            pass
        return None
    
    def _check_gif_trailing(self, file_path: str) -> Optional[Tuple[str, int]]:
        """Check for data after GIF trailer."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            trailer_offset = data.rfind(b"\x3b")
            if trailer_offset != -1 and trailer_offset + 1 < len(data):
                trailing = data[trailer_offset + 1:]
                trailing_size = len(trailing)
                if trailing_size > 10:
                    formats = self._detect_formats(trailing)
                    if formats:
                        return (list(formats)[0], trailing_size)
                    return ("unknown", trailing_size)
        except Exception:
            pass
        return None
