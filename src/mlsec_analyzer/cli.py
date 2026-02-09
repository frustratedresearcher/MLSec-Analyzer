"""Command-line interface for ML Model Security Analyzer."""

import hashlib
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, Optional

import click

from . import __version__
from .analyzer import Analyzer
from .config import DEFAULT_CONFIG, load_config
from .reporters import JSONReporter, PoCGenerator, SARIFReporter


# Exit codes
EXIT_SUCCESS = 0
EXIT_VULNERABILITIES_FOUND = 1
EXIT_SCAN_ERROR = 2

# Default checkpoint directory
DEFAULT_CHECKPOINT_DIR = ".mlsec_checkpoints"


def _format_file_size(size: int) -> str:
    """Format file size in human readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _get_file_hash(path: str, sample_size: int = 1024 * 1024) -> str:
    """Get a quick hash of file for checkpoint identification.
    
    Uses first 1MB + file size for fast identification.
    """
    file_size = os.path.getsize(path)
    hasher = hashlib.md5()
    hasher.update(str(file_size).encode())
    
    with open(path, 'rb') as f:
        hasher.update(f.read(sample_size))
    
    return hasher.hexdigest()[:16]


class ScanCheckpoint:
    """Manages scan checkpoints for resumable scanning."""
    
    def __init__(self, checkpoint_dir: str = DEFAULT_CHECKPOINT_DIR):
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(checkpoint_dir, exist_ok=True)
    
    def get_checkpoint_path(self, file_path: str) -> str:
        """Get checkpoint file path for a given model file."""
        file_hash = _get_file_hash(file_path)
        filename = os.path.basename(file_path)
        safe_name = "".join(c if c.isalnum() else "_" for c in filename)
        return os.path.join(self.checkpoint_dir, f"{safe_name}_{file_hash}.checkpoint.json")
    
    def save_checkpoint(
        self, 
        file_path: str, 
        scanner_name: str,
        bytes_scanned: int,
        total_bytes: int,
        vulnerabilities: list,
        metadata: Dict[str, Any],
    ):
        """Save scan progress to checkpoint file."""
        checkpoint = {
            "version": 1,
            "file_path": os.path.abspath(file_path),
            "file_size": os.path.getsize(file_path),
            "file_hash": _get_file_hash(file_path),
            "scanner": scanner_name,
            "bytes_scanned": bytes_scanned,
            "total_bytes": total_bytes,
            "progress_pct": int((bytes_scanned / total_bytes) * 100) if total_bytes > 0 else 0,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [v.to_dict() if hasattr(v, 'to_dict') else v for v in vulnerabilities],
            "metadata": metadata,
            "timestamp": datetime.now().isoformat(),
            "resumable": bytes_scanned < total_bytes,
        }
        
        checkpoint_path = self.get_checkpoint_path(file_path)
        with open(checkpoint_path, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, indent=2)
        
        return checkpoint_path
    
    def load_checkpoint(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Load existing checkpoint for a file if it exists and is valid."""
        checkpoint_path = self.get_checkpoint_path(file_path)
        
        if not os.path.exists(checkpoint_path):
            return None
        
        try:
            with open(checkpoint_path, 'r', encoding='utf-8') as f:
                checkpoint = json.load(f)
            
            # Validate checkpoint is for the same file
            current_hash = _get_file_hash(file_path)
            if checkpoint.get('file_hash') != current_hash:
                # File has changed, checkpoint is invalid
                os.remove(checkpoint_path)
                return None
            
            return checkpoint
        except (json.JSONDecodeError, IOError):
            return None
    
    def clear_checkpoint(self, file_path: str):
        """Remove checkpoint for a file after successful scan."""
        checkpoint_path = self.get_checkpoint_path(file_path)
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)


class ProgressBar:
    """Simple progress bar for CLI output."""
    
    def __init__(self, enabled: bool = True, width: int = 40):
        self.enabled = enabled
        self.width = width
        self.current_stage = ""
        self.current_pct = 0
        self.start_time = time.time()
        self.last_update = 0
        self.finished = False
    
    def update(self, stage: str, current: int, total: int):
        """Update progress display."""
        if not self.enabled or self.finished:
            return
        
        # Throttle updates to avoid flickering (max 10 updates/sec)
        now = time.time()
        if now - self.last_update < 0.1 and current < total:
            return
        self.last_update = now
        
        pct = int((current / total) * 100) if total > 0 else 0
        self.current_pct = pct
        self.current_stage = stage
        
        # Build progress bar using ASCII-safe characters for Windows compatibility
        filled = int(self.width * pct / 100)
        bar = "#" * filled + "-" * (self.width - filled)
        
        # Calculate elapsed time
        elapsed = now - self.start_time
        if elapsed < 60:
            elapsed_str = f"{int(elapsed)}s"
        elif elapsed < 3600:
            elapsed_str = f"{int(elapsed//60)}m {int(elapsed%60)}s"
        else:
            elapsed_str = f"{int(elapsed//3600)}h {int((elapsed%3600)//60)}m"
        
        # Truncate stage name safely
        stage_display = stage[:40] if len(stage) > 40 else stage
        
        # Print progress line (overwrite previous)
        try:
            line = f"\r  [{bar}] {pct:3d}% | {stage_display:<40} | {elapsed_str}"
            sys.stdout.write(line)
            sys.stdout.flush()
        except UnicodeEncodeError:
            # Fallback for encoding issues
            pass
    
    def finish(self, message: str = "Complete"):
        """Complete the progress bar and move to new line."""
        if not self.enabled or self.finished:
            return
        
        self.finished = True
        elapsed = time.time() - self.start_time
        
        if elapsed < 60:
            elapsed_str = f"{elapsed:.1f}s"
        elif elapsed < 3600:
            elapsed_str = f"{int(elapsed//60)}m {int(elapsed%60)}s"
        else:
            elapsed_str = f"{int(elapsed//3600)}h {int((elapsed%3600)//60)}m"
        
        try:
            # Clear the progress line and print final message
            bar = "#" * self.width
            line = f"\r  [{bar}] 100% | {message:<40} | {elapsed_str}"
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except UnicodeEncodeError:
            pass
    
    def status(self, message: str):
        """Print a status message (on new line)."""
        if not self.enabled:
            return
        try:
            sys.stdout.write(f"\n  {message}")
            sys.stdout.flush()
        except UnicodeEncodeError:
            pass


@click.group()
@click.version_option(version=__version__, prog_name="mlsec-analyzer")
def main():
    """ML Model Security Analyzer - Static security analysis for ML model files.
    
    Detects vulnerabilities in machine learning model files including:
    - Pickle deserialization attacks
    - Computational graph injection
    - Lambda layer code execution
    - Zip slip path traversal
    - And more...
    """
    pass


@main.command()
@click.argument("path", required=False)
@click.option(
    "--remote", "-r",
    help="Remote URL to download model from (HTTP/HTTPS)",
    type=str,
)
@click.option(
    "--huggingface", "-hf",
    help="HuggingFace model ID to download (e.g., 'bert-base-uncased')",
    type=str,
)
@click.option(
    "--output", "-o",
    default="report.json",
    help="Output file path for the scan report",
    type=click.Path(),
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["json", "sarif"], case_sensitive=False),
    default="json",
    help="Output format for the report",
)
@click.option(
    "--generate-poc",
    is_flag=True,
    default=False,
    help="Generate Proof of Concept files for detected vulnerabilities",
)
@click.option(
    "--poc-dir",
    default="./pocs",
    help="Directory for PoC output files",
    type=click.Path(),
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default="low",
    help="Minimum severity level to report",
)
@click.option(
    "--fail-on-critical",
    is_flag=True,
    default=False,
    help="Exit with non-zero code if critical vulnerabilities found",
)
@click.option(
    "--fail-on-high",
    is_flag=True,
    default=False,
    help="Exit with non-zero code if high or critical vulnerabilities found",
)
@click.option(
    "--config", "-c",
    "config_path",
    help="Path to custom configuration file (YAML or JSON)",
    type=click.Path(exists=True),
)
@click.option(
    "--scanners",
    help="Comma-separated list of scanners to run (default: all)",
    type=str,
)
@click.option(
    "--exclude-scanners",
    help="Comma-separated list of scanners to exclude",
    type=str,
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress non-essential output",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored output",
)
@click.option(
    "--progress/--no-progress", "-p",
    default=True,
    help="Show progress bar during scan (enabled by default)",
)
@click.option(
    "--resume/--no-resume",
    default=True,
    help="Auto-resume from checkpoint if available (enabled by default)",
)
@click.option(
    "--checkpoint-dir",
    default=DEFAULT_CHECKPOINT_DIR,
    help="Directory for checkpoint files (default: .mlsec_checkpoints)",
    type=click.Path(),
)
def scan(
    path: Optional[str],
    remote: Optional[str],
    huggingface: Optional[str],
    output: str,
    output_format: str,
    generate_poc: bool,
    poc_dir: str,
    severity_threshold: str,
    fail_on_critical: bool,
    fail_on_high: bool,
    config_path: Optional[str],
    scanners: Optional[str],
    exclude_scanners: Optional[str],
    verbose: bool,
    quiet: bool,
    no_color: bool,
    progress: bool,
    resume: bool,
    checkpoint_dir: str,
):
    """Scan a model file or directory for security vulnerabilities.
    
    Progress bar and resumable scanning are enabled by default.
    
    Examples:
    
        # Basic scan (progress and resume enabled by default)
        mlsec-analyzer scan model.pkl
        
        # Custom output path
        mlsec-analyzer scan model.pkl -o /path/to/report.json
        
        # Disable progress bar (for CI/CD logs)
        mlsec-analyzer scan model.pkl --no-progress
        
        # Force fresh scan (ignore checkpoint)
        mlsec-analyzer scan model.pkl --no-resume
        
        # Scan from HuggingFace
        mlsec-analyzer scan --huggingface bert-base-uncased
        
        # Scan with PoC generation
        mlsec-analyzer scan model.pkl --generate-poc --poc-dir ./pocs
    """
    # Validate input - exactly one source must be provided
    sources = [path, remote, huggingface]
    provided_sources = [s for s in sources if s is not None]
    
    if len(provided_sources) == 0:
        click.echo("Error: Must provide a path, --remote URL, or --huggingface model ID", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    if len(provided_sources) > 1:
        click.echo("Error: Only one source (path, --remote, or --huggingface) can be specified", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    # Load configuration
    try:
        config = load_config(config_path)
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    # Apply CLI overrides to config
    config["severity"]["threshold"] = severity_threshold
    config["severity"]["fail_on_critical"] = fail_on_critical
    config["poc"]["enabled"] = generate_poc
    config["poc"]["output_dir"] = poc_dir
    config["output"]["format"] = output_format
    
    # Parse scanner filters
    scanner_list = None
    if scanners:
        scanner_list = [s.strip() for s in scanners.split(",")]
    
    exclude_list = None
    if exclude_scanners:
        exclude_list = [s.strip() for s in exclude_scanners.split(",")]
    
    # Initialize analyzer
    analyzer = Analyzer(config, verbose=verbose, quiet=quiet)
    
    # Initialize checkpoint manager
    checkpoint_mgr = ScanCheckpoint(checkpoint_dir)
    
    # Set up progress bar
    progress_bar = None
    progress_callback = None
    
    if progress and not quiet:
        progress_bar = ProgressBar(enabled=True)
        progress_callback = progress_bar.update
    
    try:
        # Check for existing checkpoint if resume is requested
        if resume and path and os.path.isfile(path):
            checkpoint = checkpoint_mgr.load_checkpoint(path)
            if checkpoint:
                if not quiet:
                    click.echo(f"Found checkpoint from {checkpoint.get('timestamp', 'unknown')}")
                    click.echo(f"  Previous progress: {checkpoint.get('progress_pct', 0)}%")
                    click.echo(f"  Vulnerabilities found: {checkpoint.get('vulnerabilities_found', 0)}")
                    if checkpoint.get('resumable', False):
                        click.echo("  Resuming scan...")
                    else:
                        click.echo("  Checkpoint shows scan was complete. Re-scanning...")
        
        # Determine source type and scan
        if path:
            if not quiet:
                # Show file size for large files
                if os.path.isfile(path):
                    file_size = os.path.getsize(path)
                    size_str = _format_file_size(file_size)
                    click.echo(f"Scanning: {path} ({size_str})")
                    
                    # Auto-enable progress for large files (>50MB)
                    if file_size > 50 * 1024 * 1024 and not progress_bar:
                        click.echo("  Large file detected, enabling progress display...")
                        progress_bar = ProgressBar(enabled=True)
                        progress_callback = progress_bar.update
                else:
                    click.echo(f"Scanning directory: {path}")
            
            results = analyzer.scan_path(path, scanner_list, exclude_list, progress_callback)
        elif remote:
            if not quiet:
                click.echo(f"Downloading and scanning: {remote}")
            results = analyzer.scan_remote(remote, scanner_list, exclude_list)
        elif huggingface:
            if not quiet:
                click.echo(f"Downloading from HuggingFace and scanning: {huggingface}")
            results = analyzer.scan_huggingface(huggingface, scanner_list, exclude_list)
        else:
            # Should not reach here
            click.echo("Error: No source specified", err=True)
            sys.exit(EXIT_SCAN_ERROR)
        
        # Finish progress bar
        if progress_bar:
            progress_bar.finish("Scan complete")
        
        # Clear checkpoint on successful completion
        if path and os.path.isfile(path):
            checkpoint_mgr.clear_checkpoint(path)
        
        if not quiet:
            click.echo("  Generating report...")
        
        # Filter results by severity threshold
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(severity_threshold.lower())
        filtered_vulns = [
            v for v in results.vulnerabilities
            if severity_order.index(v.severity.level.lower()) <= threshold_idx
        ]
        results.vulnerabilities = filtered_vulns
        
        # Generate report
        if output_format.lower() == "json":
            reporter = JSONReporter()
        else:
            reporter = SARIFReporter()
        
        report = reporter.generate(results)
        
        # Write report
        output_path = os.path.abspath(output)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        if not quiet:
            click.echo(f"Report written to: {output_path}")
        
        # Generate PoCs if requested
        if generate_poc and results.vulnerabilities:
            poc_generator = PoCGenerator(config)
            poc_paths = poc_generator.generate_all(results.vulnerabilities, poc_dir)
            if not quiet:
                click.echo(f"Generated {len(poc_paths)} PoC files in: {poc_dir}")
        
        # Print summary
        if not quiet:
            _print_summary(results, no_color)
        
        # Determine exit code
        if results.vulnerabilities:
            critical_count = sum(1 for v in results.vulnerabilities if v.severity.level.lower() == "critical")
            high_count = sum(1 for v in results.vulnerabilities if v.severity.level.lower() == "high")
            
            if fail_on_critical and critical_count > 0:
                sys.exit(EXIT_VULNERABILITIES_FOUND)
            if fail_on_high and (critical_count > 0 or high_count > 0):
                sys.exit(EXIT_VULNERABILITIES_FOUND)
        
        sys.exit(EXIT_SUCCESS)
        
    except KeyboardInterrupt:
        click.echo("\nScan interrupted by user", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    except Exception as e:
        if verbose:
            import traceback
            traceback.print_exc()
        click.echo(f"Error during scan: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)


def _print_summary(results, no_color: bool):
    """Print a summary of scan results."""
    click.echo("\n" + "=" * 60)
    click.echo("SCAN SUMMARY")
    click.echo("=" * 60)
    
    total = len(results.vulnerabilities)
    critical = sum(1 for v in results.vulnerabilities if v.severity.level.lower() == "critical")
    high = sum(1 for v in results.vulnerabilities if v.severity.level.lower() == "high")
    medium = sum(1 for v in results.vulnerabilities if v.severity.level.lower() == "medium")
    low = sum(1 for v in results.vulnerabilities if v.severity.level.lower() == "low")
    
    click.echo(f"Total vulnerabilities found: {total}")
    
    if no_color:
        click.echo(f"  Critical: {critical}")
        click.echo(f"  High:     {high}")
        click.echo(f"  Medium:   {medium}")
        click.echo(f"  Low:      {low}")
    else:
        click.echo(click.style(f"  Critical: {critical}", fg="red" if critical > 0 else None))
        click.echo(click.style(f"  High:     {high}", fg="yellow" if high > 0 else None))
        click.echo(click.style(f"  Medium:   {medium}", fg="cyan" if medium > 0 else None))
        click.echo(f"  Low:      {low}")
    
    click.echo("=" * 60)
    
    # List vulnerabilities
    if results.vulnerabilities:
        click.echo("\nVulnerabilities:")
        for vuln in results.vulnerabilities:
            severity_color = {
                "critical": "red",
                "high": "yellow",
                "medium": "cyan",
                "low": None,
            }.get(vuln.severity.level.lower())
            
            if no_color:
                click.echo(f"  [{vuln.severity.level.upper()}] {vuln.vulnerability_type}")
            else:
                severity_text = click.style(f"[{vuln.severity.level.upper()}]", fg=severity_color)
                click.echo(f"  {severity_text} {vuln.vulnerability_type}")
            click.echo(f"      File: {vuln.location.get('file', 'N/A')}")
            # Sanitize description for console output (remove non-ASCII)
            desc = vuln.description[:80]
            try:
                desc.encode('charmap')
            except UnicodeEncodeError:
                desc = desc.encode('ascii', errors='replace').decode('ascii')
            click.echo(f"      {desc}...")
    else:
        click.echo("\nNo vulnerabilities found!")


@main.command()
def list_scanners():
    """List all available vulnerability scanners."""
    from .scanners import SCANNER_REGISTRY
    
    click.echo("Available Scanners:")
    click.echo("-" * 60)
    
    for name, scanner_class in SCANNER_REGISTRY.items():
        scanner = scanner_class({})
        click.echo(f"\n{name}:")
        click.echo(f"  Name: {scanner.get_name()}")
        click.echo(f"  Formats: {', '.join(scanner.get_supported_formats())}")
        click.echo(f"  Description: {scanner.get_description()}")


@main.command()
@click.option("--output", "-o", default="config.yaml", help="Output path for config file")
def init_config(output: str):
    """Generate a default configuration file."""
    import yaml
    
    output_path = os.path.abspath(output)
    
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
    
    click.echo(f"Configuration file created: {output_path}")


@main.command()
def supported_formats():
    """List all supported model file formats."""
    from .utils import ModelFormatDetector
    
    detector = ModelFormatDetector()
    formats = detector.get_supported_formats()
    
    click.echo("Supported Model Formats:")
    click.echo("-" * 40)
    
    for fmt in formats:
        click.echo(f"  {fmt.extension:12} - {fmt.description}")


@main.command("generate-poc")
@click.argument("report_file", type=click.Path(exists=True))
@click.option(
    "--output-dir", "-o",
    default="./pocs",
    help="Directory for PoC output files (default: ./pocs)",
    type=click.Path(),
)
@click.option(
    "--config", "-c",
    "config_path",
    help="Path to custom configuration file (YAML or JSON)",
    type=click.Path(exists=True),
)
@click.option(
    "--format", "-f",
    "poc_format",
    type=click.Choice(["python", "json", "both"], case_sensitive=False),
    default="both",
    help="PoC output format (default: both)",
)
def generate_poc_from_report(
    report_file: str,
    output_dir: str,
    config_path: Optional[str],
    poc_format: str,
):
    """Generate PoC files from an existing scan report.
    
    Use this command if you forgot to pass --generate-poc during the initial scan,
    or if you want to regenerate PoCs with different settings.
    
    Examples:
    
        # Generate PoCs from a report file
        mlsec-analyzer generate-poc report.json
        
        # Custom output directory
        mlsec-analyzer generate-poc report.json -o ./my_pocs
        
        # Generate only Python PoCs
        mlsec-analyzer generate-poc report.json --format python
    """
    from .scanners.base_scanner import Severity, Vulnerability
    
    # Load configuration
    try:
        config = load_config(config_path)
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    # Set PoC formats based on CLI option
    if poc_format == "both":
        config.setdefault("poc", {})["formats"] = ["python", "json"]
    else:
        config.setdefault("poc", {})["formats"] = [poc_format]
    
    # Load the report file
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in report file: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    except Exception as e:
        click.echo(f"Error reading report file: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    # Check if report has vulnerabilities
    vulns_data = report.get("vulnerabilities", [])
    if not vulns_data:
        click.echo("No vulnerabilities found in report. Nothing to generate.")
        sys.exit(EXIT_SUCCESS)
    
    click.echo(f"Found {len(vulns_data)} vulnerabilities in report")
    
    # Convert vulnerability dicts back to Vulnerability objects
    vulnerabilities = []
    for v in vulns_data:
        try:
            # Reconstruct Severity object
            severity_data = v.get("severity", {})
            if isinstance(severity_data, dict):
                severity = Severity(
                    level=severity_data.get("level", "Medium"),
                    cvss_score=severity_data.get("cvss_score", 5.0),
                    cvss_vector=severity_data.get("cvss_vector", ""),
                )
            else:
                severity = Severity(level=str(severity_data))
            
            # Create Vulnerability object
            vuln = Vulnerability(
                id=v.get("id", "UNKNOWN"),
                scanner=v.get("scanner", "Unknown"),
                vulnerability_type=v.get("vulnerability_type", "Unknown"),
                severity=severity,
                description=v.get("description", ""),
                location=v.get("location", {}),
                evidence=v.get("evidence", {}),
                recommendation=v.get("recommendation", ""),
                references=v.get("references", []),
                cwe_id=v.get("cwe_id"),
                cve_id=v.get("cve_id"),
            )
            vulnerabilities.append(vuln)
        except Exception as e:
            click.echo(f"Warning: Could not parse vulnerability {v.get('id', '?')}: {e}", err=True)
    
    if not vulnerabilities:
        click.echo("Error: Could not parse any vulnerabilities from report", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    # Generate PoCs
    try:
        poc_generator = PoCGenerator(config)
        poc_paths = poc_generator.generate_all(vulnerabilities, output_dir)
        
        click.echo(f"\nGenerated {len(poc_paths)} PoC files in: {os.path.abspath(output_dir)}")
        click.echo("-" * 40)
        for path in poc_paths:
            click.echo(f"  {os.path.basename(path)}")
        
    except Exception as e:
        click.echo(f"Error generating PoCs: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    sys.exit(EXIT_SUCCESS)


@main.command("generate-testcases")
@click.argument("format_name")
@click.option(
    "-o", "--output-dir",
    default="./testcases",
    help="Output directory for generated test cases",
)
@click.option(
    "-t", "--type",
    "vuln_type",
    default=None,
    help="Generate only a specific vulnerability type",
)
@click.option(
    "--list-types",
    is_flag=True,
    help="List available vulnerability types for the format",
)
@click.option(
    "--list-formats",
    is_flag=True,
    help="List all supported formats",
)
def generate_testcases(format_name: str, output_dir: str, vuln_type: Optional[str], list_types: bool, list_formats: bool):
    """Generate malicious test case files for security testing.
    
    Creates model files containing exploit payloads that target known
    parser/loader vulnerabilities. Use for testing scanner detection
    and security research.
    
    FORMAT_NAME: File format to generate (gguf, pickle, keras, zipslip, numpy, tensorflow)
    
    Examples:
    
    \b
        # List all supported formats
        mlsec-analyzer generate-testcases --list-formats
        
    \b
        # Generate all GGUF exploit test cases
        mlsec-analyzer generate-testcases gguf
        
    \b
        # Generate all pickle exploit test cases
        mlsec-analyzer generate-testcases pickle -o ./malicious_samples
        
    \b
        # List vulnerability types for Keras
        mlsec-analyzer generate-testcases keras --list-types
        
    \b
        # Generate specific vulnerability type
        mlsec-analyzer generate-testcases gguf -t dimension_overflow
    
    WARNING: Generated files contain REAL exploit payloads. Use only in
    isolated test environments.
    """
    from .generators import get_generator, list_formats as get_all_formats, GENERATORS
    
    # Handle --list-formats with any format name
    if list_formats:
        click.echo("Supported formats:")
        click.echo("-" * 40)
        for fmt in sorted(get_all_formats()):
            generator = GENERATORS[fmt]()
            click.echo(f"  {fmt:12} - {len(generator.get_vulnerability_types())} vulnerability types")
            click.echo(f"               Extensions: {', '.join(generator.get_format_extensions())}")
        sys.exit(EXIT_SUCCESS)
    
    # Get generator for format
    try:
        generator = get_generator(format_name)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(EXIT_SCAN_ERROR)
    
    # Handle --list-types
    if list_types:
        click.echo(f"Vulnerability types for {format_name}:")
        click.echo("-" * 40)
        for vtype in generator.get_vulnerability_types():
            click.echo(f"  {vtype}")
        sys.exit(EXIT_SUCCESS)
    
    # Create output directory
    format_output_dir = os.path.join(output_dir, format_name)
    os.makedirs(format_output_dir, exist_ok=True)
    
    click.echo("=" * 60)
    click.echo(f"ML Model Security Analyzer - Test Case Generator")
    click.echo("=" * 60)
    click.echo()
    click.echo(f"Format: {format_name}")
    click.echo(f"Output: {os.path.abspath(format_output_dir)}")
    click.echo()
    click.echo("WARNING: Generated files contain REAL exploit payloads!")
    click.echo("Use only in isolated test environments.")
    click.echo()
    click.echo("-" * 60)
    
    try:
        if vuln_type:
            # Generate specific type
            click.echo(f"Generating: {vuln_type}")
            tc = generator.generate_specific(vuln_type, format_output_dir)
            if tc:
                testcases = [tc]
                click.echo(f"  [OK] {tc.filename}")
                click.echo(f"       Target: {tc.target_parser}")
                if tc.cve_id:
                    click.echo(f"       CVE: {tc.cve_id}")
            else:
                click.echo(f"Error: Unknown vulnerability type: {vuln_type}", err=True)
                click.echo(f"Use --list-types to see available types")
                sys.exit(EXIT_SCAN_ERROR)
        else:
            # Generate all types
            click.echo(f"Generating all {len(generator.get_vulnerability_types())} vulnerability types...")
            click.echo()
            
            testcases = generator.generate_all(format_output_dir)
            
            for tc in testcases:
                click.echo(f"  [OK] {tc.filename}")
                click.echo(f"       Type: {tc.vulnerability_type}")
                click.echo(f"       Target: {tc.target_parser}")
                if tc.cve_id:
                    click.echo(f"       CVE: {tc.cve_id}")
                click.echo()
        
        # Summary
        click.echo("-" * 60)
        click.echo(f"Generated {len(testcases)} test case(s)")
        click.echo(f"Output directory: {os.path.abspath(format_output_dir)}")
        click.echo()
        
        # Create manifest file
        manifest = {
            "format": format_name,
            "generator": "mlsec-analyzer",
            "generated_at": datetime.now().isoformat(),
            "testcases": [
                {
                    "filename": tc.filename,
                    "vulnerability_type": tc.vulnerability_type,
                    "target_parser": tc.target_parser,
                    "cve_id": tc.cve_id,
                    "severity": tc.severity,
                    "description": tc.description,
                }
                for tc in testcases
            ],
        }
        manifest_path = os.path.join(format_output_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        click.echo(f"Manifest written to: {manifest_path}")
        
    except Exception as e:
        click.echo(f"Error generating test cases: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(EXIT_SCAN_ERROR)
    
    sys.exit(EXIT_SUCCESS)


@main.command("list-formats")
def list_all_formats():
    """List all supported file formats for test case generation."""
    from .generators import list_formats as get_all_formats, GENERATORS
    
    click.echo("Supported formats for test case generation:")
    click.echo("=" * 60)
    
    for fmt in sorted(get_all_formats()):
        generator = GENERATORS[fmt]()
        click.echo(f"\n{fmt.upper()}")
        click.echo("-" * 40)
        click.echo(f"  Extensions: {', '.join(generator.get_format_extensions())}")
        click.echo(f"  Vulnerability types: {len(generator.get_vulnerability_types())}")
        for vtype in generator.get_vulnerability_types():
            click.echo(f"    - {vtype}")
    
    sys.exit(EXIT_SUCCESS)


if __name__ == "__main__":
    main()
