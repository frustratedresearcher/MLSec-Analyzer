"""Zip Slip path traversal vulnerability scanner."""

import os
import tarfile
import zipfile
from typing import Any, Dict, List, Tuple

from .base_scanner import BaseScanner, ScanResult, Severity, Vulnerability


class ZipSlipScanner(BaseScanner):
    """Scanner for Zip Slip path traversal vulnerabilities.
    
    Detects archive files containing entries with path traversal
    sequences that could overwrite files outside the extraction directory.
    """
    
    # Path traversal patterns
    TRAVERSAL_PATTERNS = [
        "..",
        "../",
        "..\\",
    ]
    
    def get_name(self) -> str:
        return "Zip Slip Scanner"
    
    def get_supported_formats(self) -> List[str]:
        return [".zip", ".npz", ".keras", ".pth", ".pt", ".tar", ".tar.gz", ".tgz", ".whl"]
    
    def get_description(self) -> str:
        return "Detects path traversal vulnerabilities in archive-based model files"
    
    def scan(self, model_path: str, global_config: Dict[str, Any]) -> ScanResult:
        """Scan an archive for Zip Slip vulnerabilities."""
        result = ScanResult(scanner_name=self.get_name())
        
        if not os.path.exists(model_path):
            result.add_error(f"File not found: {model_path}")
            return result
        
        ext = os.path.splitext(model_path)[1].lower()
        
        # Determine archive type
        if model_path.lower().endswith((".tar.gz", ".tgz")):
            return self._scan_tar(model_path, result, "r:gz")
        elif model_path.lower().endswith(".tar.bz2"):
            return self._scan_tar(model_path, result, "r:bz2")
        elif ext == ".tar":
            return self._scan_tar(model_path, result, "r:")
        elif ext in [".zip", ".npz", ".keras", ".pth", ".pt", ".whl"]:
            return self._scan_zip(model_path, result)
        
        # Try to detect format
        try:
            if zipfile.is_zipfile(model_path):
                return self._scan_zip(model_path, result)
        except Exception:
            pass
        
        try:
            if tarfile.is_tarfile(model_path):
                return self._scan_tar(model_path, result, "r:*")
        except Exception:
            pass
        
        result.add_warning("Unable to determine archive format")
        return result
    
    def _scan_zip(self, file_path: str, result: ScanResult) -> ScanResult:
        """Scan a ZIP archive for path traversal."""
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                # Get all entry names
                entries = zf.namelist()
                
                # Check for path traversal
                traversal_entries = self._find_traversal_entries(entries)
                
                if traversal_entries:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Zip Slip - Path Traversal",
                        severity=Severity.high(7.5),
                        description=(
                            f"Archive contains {len(traversal_entries)} entries with path "
                            f"traversal sequences that could overwrite files outside the "
                            f"extraction directory."
                        ),
                        location={"file": file_path},
                        evidence={
                            "malicious_entries": traversal_entries[:10],
                            "total_malicious": len(traversal_entries),
                        },
                        recommendation=(
                            "Do not extract this archive. The path traversal entries "
                            "could overwrite critical system files."
                        ),
                        references=[
                            "https://research.jfrog.com/model-threats/zipslip/",
                            "https://snyk.io/research/zip-slip-vulnerability",
                        ],
                        cwe_id="CWE-22",
                    )
                    result.add_vulnerability(vuln)
                
                # Check for symlinks (ZipInfo external_attr)
                symlink_entries = self._find_symlink_entries_zip(zf)
                
                if symlink_entries:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Zip Slip - Symlink Attack",
                        severity=Severity.high(7.0),
                        description=(
                            f"Archive contains {len(symlink_entries)} symlink entries that "
                            f"could be used to access files outside the extraction directory."
                        ),
                        location={"file": file_path},
                        evidence={
                            "symlink_entries": symlink_entries[:10],
                            "total_symlinks": len(symlink_entries),
                        },
                        recommendation=(
                            "Do not extract this archive with symlink following enabled."
                        ),
                        references=[
                            "https://research.jfrog.com/model-threats/zipslip/",
                        ],
                        cwe_id="CWE-59",
                    )
                    result.add_vulnerability(vuln)
                
                # Check for absolute paths
                absolute_entries = self._find_absolute_paths(entries)
                
                if absolute_entries:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Zip Slip - Absolute Path",
                        severity=Severity.medium(6.0),
                        description=(
                            f"Archive contains {len(absolute_entries)} entries with absolute "
                            f"paths that may extract to unexpected locations."
                        ),
                        location={"file": file_path},
                        evidence={
                            "absolute_entries": absolute_entries[:10],
                            "total_absolute": len(absolute_entries),
                        },
                        recommendation=(
                            "Review extraction behavior for absolute paths."
                        ),
                        references=[
                            "https://research.jfrog.com/model-threats/zipslip/",
                        ],
                        cwe_id="CWE-22",
                    )
                    result.add_vulnerability(vuln)
                
                # Check for header/central directory mismatch (CVE-2025-1944)
                mismatches = self._check_header_mismatches(zf, file_path)
                
                if mismatches:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Zip Slip - Header Mismatch",
                        severity=Severity.high(7.5),
                        description=(
                            "Archive has mismatches between local headers and central "
                            "directory. This may be used to bypass security scanners."
                        ),
                        location={"file": file_path},
                        evidence={
                            "mismatches": mismatches[:5],
                        },
                        recommendation=(
                            "This archive may be crafted to bypass scanning tools. "
                            "Do not trust automated scan results for this file."
                        ),
                        references=[
                            "https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/",
                        ],
                        cwe_id="CWE-22",
                        cve_id="CVE-2025-1944",
                    )
                    result.add_vulnerability(vuln)
                    
        except zipfile.BadZipFile as e:
            result.add_error(f"Invalid ZIP file: {e}")
        except Exception as e:
            result.add_error(f"Failed to scan ZIP: {e}")
        
        return result
    
    def _scan_tar(self, file_path: str, result: ScanResult, mode: str) -> ScanResult:
        """Scan a TAR archive for path traversal."""
        try:
            with tarfile.open(file_path, mode) as tf:
                entries = [m.name for m in tf.getmembers()]
                
                # Check for path traversal
                traversal_entries = self._find_traversal_entries(entries)
                
                if traversal_entries:
                    vuln = self._create_vulnerability(
                        vulnerability_type="Tar Slip - Path Traversal",
                        severity=Severity.high(7.5),
                        description=(
                            f"Archive contains {len(traversal_entries)} entries with path "
                            f"traversal sequences."
                        ),
                        location={"file": file_path},
                        evidence={
                            "malicious_entries": traversal_entries[:10],
                            "total_malicious": len(traversal_entries),
                        },
                        recommendation=(
                            "Do not extract this archive."
                        ),
                        references=[
                            "https://research.jfrog.com/model-threats/zipslip/",
                        ],
                        cwe_id="CWE-22",
                    )
                    result.add_vulnerability(vuln)
                
                # Check for symlinks
                symlink_members = [m for m in tf.getmembers() if m.issym() or m.islnk()]
                
                if symlink_members:
                    # Check if any symlinks point outside
                    dangerous_symlinks = []
                    for m in symlink_members:
                        if m.linkname.startswith("/") or ".." in m.linkname:
                            dangerous_symlinks.append({
                                "name": m.name,
                                "target": m.linkname,
                            })
                    
                    if dangerous_symlinks:
                        vuln = self._create_vulnerability(
                            vulnerability_type="Tar Slip - Dangerous Symlink",
                            severity=Severity.high(7.5),
                            description=(
                                f"Archive contains {len(dangerous_symlinks)} symlinks "
                                f"pointing to dangerous locations."
                            ),
                            location={"file": file_path},
                            evidence={
                                "dangerous_symlinks": dangerous_symlinks[:10],
                            },
                            recommendation=(
                                "Do not extract symlinks from this archive."
                            ),
                            references=[],
                            cwe_id="CWE-59",
                        )
                        result.add_vulnerability(vuln)
                        
        except tarfile.TarError as e:
            result.add_error(f"Invalid TAR file: {e}")
        except Exception as e:
            result.add_error(f"Failed to scan TAR: {e}")
        
        return result
    
    def _find_traversal_entries(self, entries: List[str]) -> List[str]:
        """Find entries with path traversal sequences."""
        dangerous = []
        
        for entry in entries:
            normalized = os.path.normpath(entry)
            
            # Check for .. in path
            if ".." in entry or normalized.startswith(".."):
                dangerous.append(entry)
                continue
            
            # Check each component
            parts = entry.replace("\\", "/").split("/")
            for part in parts:
                if part == "..":
                    dangerous.append(entry)
                    break
        
        return dangerous
    
    def _find_absolute_paths(self, entries: List[str]) -> List[str]:
        """Find entries with absolute paths."""
        absolute = []
        
        for entry in entries:
            if entry.startswith("/") or (len(entry) > 1 and entry[1] == ":"):
                absolute.append(entry)
        
        return absolute
    
    def _find_symlink_entries_zip(self, zf: zipfile.ZipFile) -> List[Dict]:
        """Find symlink entries in a ZIP file."""
        symlinks = []
        
        for info in zf.infolist():
            # Check Unix symlink mode (0xA000 in high byte)
            # external_attr >> 16 gives Unix mode
            unix_mode = info.external_attr >> 16
            if unix_mode & 0o170000 == 0o120000:  # S_IFLNK
                symlinks.append({
                    "name": info.filename,
                    "mode": oct(unix_mode),
                })
        
        return symlinks
    
    def _check_header_mismatches(
        self, zf: zipfile.ZipFile, file_path: str
    ) -> List[Dict]:
        """Check for header/central directory mismatches."""
        mismatches = []
        
        try:
            # Read raw file to check local headers
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Local file header signature
            LOCAL_HEADER_SIG = b"PK\x03\x04"
            
            pos = 0
            local_names = []
            
            while True:
                pos = data.find(LOCAL_HEADER_SIG, pos)
                if pos == -1:
                    break
                
                try:
                    # Parse local header
                    # Skip to filename length at offset 26
                    name_len = int.from_bytes(data[pos + 26:pos + 28], "little")
                    extra_len = int.from_bytes(data[pos + 28:pos + 30], "little")
                    
                    # Filename starts at offset 30
                    filename = data[pos + 30:pos + 30 + name_len].decode("utf-8", errors="replace")
                    local_names.append(filename)
                    
                    pos += 30 + name_len + extra_len
                except Exception:
                    pos += 1
            
            # Compare with central directory
            central_names = zf.namelist()
            
            # Check for discrepancies
            local_set = set(local_names)
            central_set = set(central_names)
            
            only_local = local_set - central_set
            only_central = central_set - local_set
            
            if only_local or only_central:
                mismatches.append({
                    "only_in_local_headers": list(only_local)[:5],
                    "only_in_central_directory": list(only_central)[:5],
                })
                
        except Exception:
            # If we can't check, don't report
            pass
        
        return mismatches
