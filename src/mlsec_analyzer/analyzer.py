"""Core analyzer orchestrating model extraction and vulnerability scanning."""

import os
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .extractor import ModelExtractor
from .scanners import SCANNER_REGISTRY, BaseScanner, ScanResult, Vulnerability
from .utils import ModelFormatDetector


# Type alias for progress callback
ProgressCallback = Optional[Callable[[str, int, int], None]]


@dataclass
class AnalysisResult:
    """Results from a complete analysis run."""
    
    scan_metadata: Dict[str, Any]
    vulnerabilities: List[Vulnerability]
    summary: Dict[str, int]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scanner_metadata: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "scan_metadata": self.scan_metadata,
            "summary": self.summary,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
        if self.errors:
            result["errors"] = self.errors
        if self.warnings:
            result["warnings"] = self.warnings
        if self.scanner_metadata:
            result["scanner_metadata"] = self.scanner_metadata
        return result


class Analyzer:
    """Main analyzer class that orchestrates scanning."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        verbose: bool = False,
        quiet: bool = False,
    ):
        """Initialize the analyzer.
        
        Args:
            config: Configuration dictionary.
            verbose: Enable verbose output.
            quiet: Suppress non-essential output.
        """
        self.config = config
        self.verbose = verbose
        self.quiet = quiet
        self.extractor = ModelExtractor(config)
        self.format_detector = ModelFormatDetector()
        self._scanners: Dict[str, BaseScanner] = {}
        self._initialize_scanners()
    
    def _initialize_scanners(self):
        """Initialize all enabled scanners."""
        scanner_configs = self.config.get("scanners", {})
        
        for scanner_name, scanner_class in SCANNER_REGISTRY.items():
            scanner_config = scanner_configs.get(f"{scanner_name}_scanner", {})
            
            if scanner_config.get("enabled", True):
                self._scanners[scanner_name] = scanner_class(scanner_config)
                if self.verbose:
                    print(f"Initialized scanner: {scanner_name}")
    
    def _log(self, message: str):
        """Log a message if not in quiet mode."""
        if not self.quiet:
            print(message)
    
    def _log_verbose(self, message: str):
        """Log a message if in verbose mode."""
        if self.verbose:
            print(f"[VERBOSE] {message}")
    
    def _format_size(self, size: int) -> str:
        """Format file size in human readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    
    def scan_path(
        self,
        path: str,
        include_scanners: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
        progress_callback: ProgressCallback = None,
    ) -> AnalysisResult:
        """Scan a local file or directory.
        
        Args:
            path: Path to file or directory to scan.
            include_scanners: List of scanner names to run (None = all).
            exclude_scanners: List of scanner names to exclude.
            progress_callback: Optional callback for progress updates.
                              Signature: (stage: str, current: int, total: int) -> None
            
        Returns:
            AnalysisResult containing all findings.
        """
        path = os.path.abspath(path)
        
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")
        
        if os.path.isfile(path):
            return self._scan_file(path, include_scanners, exclude_scanners, progress_callback)
        elif os.path.isdir(path):
            return self._scan_directory(path, include_scanners, exclude_scanners, progress_callback)
        else:
            raise ValueError(f"Invalid path: {path}")
    
    def scan_remote(
        self,
        url: str,
        include_scanners: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Download and scan a model from a remote URL.
        
        Args:
            url: HTTP/HTTPS URL to download from.
            include_scanners: List of scanner names to run (None = all).
            exclude_scanners: List of scanner names to exclude.
            
        Returns:
            AnalysisResult containing all findings.
        """
        self._log(f"Downloading from: {url}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = self.extractor.download_http(url, temp_dir)
            return self._scan_file(local_path, include_scanners, exclude_scanners)
    
    def scan_huggingface(
        self,
        model_id: str,
        include_scanners: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Download and scan a model from HuggingFace Hub.
        
        Args:
            model_id: HuggingFace model identifier.
            include_scanners: List of scanner names to run (None = all).
            exclude_scanners: List of scanner names to exclude.
            
        Returns:
            AnalysisResult containing all findings.
        """
        self._log(f"Downloading from HuggingFace: {model_id}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            local_path = self.extractor.download_huggingface(model_id, temp_dir)
            return self._scan_directory(local_path, include_scanners, exclude_scanners)
    
    def _scan_file(
        self,
        file_path: str,
        include_scanners: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
        progress_callback: ProgressCallback = None,
    ) -> AnalysisResult:
        """Scan a single file."""
        self._log_verbose(f"Scanning file: {file_path}")
        
        # Report file size for large file handling
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # > 100MB
            self._log(f"Large file detected: {self._format_size(file_size)}")
        
        # Detect format
        model_format = self.format_detector.detect(file_path)
        self._log_verbose(f"Detected format: {model_format}")
        
        # Extract if archive
        extract_dir = None
        files_to_scan = [file_path]
        
        if self.extractor.is_archive(file_path):
            self._log_verbose("Extracting archive...")
            extract_dir = tempfile.mkdtemp()
            extracted_files = self.extractor.extract_archive(file_path, extract_dir)
            files_to_scan.extend(extracted_files)
        
        # Run scanners
        all_vulnerabilities: List[Vulnerability] = []
        scanners_executed: List[str] = []
        errors: List[str] = []
        warnings: List[str] = []
        scanner_metadata: Dict[str, Dict[str, Any]] = {}
        
        scanners_to_run = self._get_scanners_to_run(
            include_scanners, exclude_scanners, model_format
        )
        
        total_scanners = len(scanners_to_run)
        for idx, (scanner_name, scanner) in enumerate(scanners_to_run.items()):
            self._log_verbose(f"Running scanner: {scanner_name}")
            scanners_executed.append(scanner_name)
            
            # Update progress for scanner start
            if progress_callback:
                pct = int((idx / total_scanners) * 100) if total_scanners > 0 else 0
                progress_callback(f"Running {scanner_name}", pct, 100)
            
            try:
                for scan_file in files_to_scan:
                    # Check if scanner supports this format
                    file_ext = os.path.splitext(scan_file)[1].lower()
                    file_format = self.format_detector.detect(scan_file)
                    supported = scanner.get_supported_formats()
                    
                    # Check if scanner supports the file (by extension, format name, or wildcard)
                    if (file_ext in supported or 
                        file_format in supported or 
                        f".{file_format}" in supported or
                        "*" in supported):
                        # Pass progress callback if scanner supports it
                        if hasattr(scanner, 'scan') and 'progress_callback' in scanner.scan.__code__.co_varnames:
                            result = scanner.scan(scan_file, self.config, progress_callback=progress_callback)
                        else:
                            result = scanner.scan(scan_file, self.config)
                        all_vulnerabilities.extend(result.vulnerabilities)
                        
                        # Capture warnings from scanner
                        if hasattr(result, 'warnings') and result.warnings:
                            for w in result.warnings:
                                warnings.append(f"[{scanner_name}] {w}")
                        
                        # Capture scanner metadata
                        if hasattr(result, 'metadata') and result.metadata:
                            if scanner_name not in scanner_metadata:
                                scanner_metadata[scanner_name] = {}
                            scanner_metadata[scanner_name].update(result.metadata)
                            
            except Exception as e:
                error_msg = f"Scanner {scanner_name} failed: {str(e)}"
                errors.append(error_msg)
                if self.verbose:
                    import traceback
                    traceback.print_exc()
        
        # Clean up extracted files
        if extract_dir and self.config.get("extraction", {}).get("cleanup_on_exit", True):
            import shutil
            shutil.rmtree(extract_dir, ignore_errors=True)
        
        # Build result
        return self._build_result(
            target=file_path,
            target_format=model_format,
            scanners_executed=scanners_executed,
            vulnerabilities=all_vulnerabilities,
            errors=errors,
            warnings=warnings,
            scanner_metadata=scanner_metadata,
        )
    
    def _scan_directory(
        self,
        dir_path: str,
        include_scanners: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
        progress_callback: ProgressCallback = None,
    ) -> AnalysisResult:
        """Scan all model files in a directory."""
        self._log_verbose(f"Scanning directory: {dir_path}")
        
        all_vulnerabilities: List[Vulnerability] = []
        scanners_executed: set = set()
        errors: List[str] = []
        
        # Find all model files
        model_files = self._find_model_files(dir_path)
        self._log(f"Found {len(model_files)} model files to scan")
        
        total_files = len(model_files)
        for idx, file_path in enumerate(model_files):
            try:
                # Update progress
                if progress_callback:
                    pct = int((idx / total_files) * 100) if total_files > 0 else 0
                    progress_callback(f"Scanning file {idx+1}/{total_files}", pct, 100)
                
                result = self._scan_file(file_path, include_scanners, exclude_scanners, progress_callback)
                all_vulnerabilities.extend(result.vulnerabilities)
                scanners_executed.update(result.scan_metadata.get("scanners_executed", []))
                errors.extend(result.errors)
            except Exception as e:
                errors.append(f"Failed to scan {file_path}: {str(e)}")
        
        return self._build_result(
            target=dir_path,
            target_format="directory",
            scanners_executed=list(scanners_executed),
            vulnerabilities=all_vulnerabilities,
            errors=errors,
        )
    
    def _find_model_files(self, dir_path: str) -> List[str]:
        """Find all model files in a directory."""
        model_files = []
        supported_extensions = self.format_detector.get_all_extensions()
        
        for root, _, files in os.walk(dir_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in supported_extensions:
                    model_files.append(os.path.join(root, file))
        
        return model_files
    
    def _get_scanners_to_run(
        self,
        include_scanners: Optional[List[str]],
        exclude_scanners: Optional[List[str]],
        model_format: str,
    ) -> Dict[str, BaseScanner]:
        """Get the list of scanners to run based on filters."""
        scanners = {}
        
        for name, scanner in self._scanners.items():
            # Check include filter
            if include_scanners and name not in include_scanners:
                continue
            
            # Check exclude filter
            if exclude_scanners and name in exclude_scanners:
                continue
            
            scanners[name] = scanner
        
        return scanners
    
    def _build_result(
        self,
        target: str,
        target_format: str,
        scanners_executed: List[str],
        vulnerabilities: List[Vulnerability],
        errors: List[str],
        warnings: Optional[List[str]] = None,
        scanner_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> AnalysisResult:
        """Build the final analysis result."""
        # Calculate summary
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "critical": sum(1 for v in vulnerabilities if v.severity.level.lower() == "critical"),
            "high": sum(1 for v in vulnerabilities if v.severity.level.lower() == "high"),
            "medium": sum(1 for v in vulnerabilities if v.severity.level.lower() == "medium"),
            "low": sum(1 for v in vulnerabilities if v.severity.level.lower() == "low"),
        }
        
        # Build metadata
        scan_metadata = {
            "tool_version": "1.0.0",
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "target": target,
            "target_format": target_format,
            "scanners_executed": scanners_executed,
        }
        
        return AnalysisResult(
            scan_metadata=scan_metadata,
            vulnerabilities=vulnerabilities,
            summary=summary,
            errors=errors,
            warnings=warnings or [],
            scanner_metadata=scanner_metadata or {},
        )
