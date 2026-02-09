"""Model file extraction from various sources."""

import os
import shutil
import tarfile
import tempfile
import zipfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class ModelExtractor:
    """Handles extraction of model files from various sources."""
    
    ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".npz"}
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the extractor.
        
        Args:
            config: Configuration dictionary.
        """
        self.config = config
        self.max_file_size = config.get("extraction", {}).get("max_file_size_mb", 500) * 1024 * 1024
        self.timeout = config.get("extraction", {}).get("timeout_seconds", 300)
    
    def is_archive(self, file_path: str) -> bool:
        """Check if a file is an archive.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            True if the file is an archive.
        """
        ext = os.path.splitext(file_path)[1].lower()
        
        # Check for double extensions like .tar.gz
        if file_path.lower().endswith(".tar.gz"):
            return True
        if file_path.lower().endswith(".tar.bz2"):
            return True
        
        # Check for zip-based formats that should be treated as archives for extraction
        # but also scanned as model files (.pth, .keras, etc.)
        zip_based_extensions = {".zip", ".npz"}
        
        return ext in zip_based_extensions or ext in {".tar", ".tgz"}
    
    def extract_archive(self, archive_path: str, extract_dir: str) -> List[str]:
        """Extract an archive to a directory.
        
        Args:
            archive_path: Path to the archive file.
            extract_dir: Directory to extract to.
            
        Returns:
            List of extracted file paths.
        """
        extracted_files = []
        
        if archive_path.lower().endswith((".tar.gz", ".tgz")):
            extracted_files = self._extract_tar(archive_path, extract_dir, "r:gz")
        elif archive_path.lower().endswith(".tar.bz2"):
            extracted_files = self._extract_tar(archive_path, extract_dir, "r:bz2")
        elif archive_path.lower().endswith(".tar"):
            extracted_files = self._extract_tar(archive_path, extract_dir, "r:")
        elif archive_path.lower().endswith((".zip", ".npz")):
            extracted_files = self._extract_zip(archive_path, extract_dir)
        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")
        
        return extracted_files
    
    def _extract_zip(self, zip_path: str, extract_dir: str) -> List[str]:
        """Extract a ZIP archive safely.
        
        Args:
            zip_path: Path to the ZIP file.
            extract_dir: Directory to extract to.
            
        Returns:
            List of extracted file paths.
        """
        extracted_files = []
        
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                # Security check: prevent zip slip
                member_path = os.path.normpath(member)
                if member_path.startswith("..") or os.path.isabs(member_path):
                    continue  # Skip potentially dangerous paths
                
                target_path = os.path.join(extract_dir, member_path)
                
                # Ensure we don't extract outside the target directory
                real_extract_dir = os.path.realpath(extract_dir)
                real_target_path = os.path.realpath(target_path)
                
                if not real_target_path.startswith(real_extract_dir):
                    continue  # Skip path traversal attempts
                
                if member.endswith("/"):
                    os.makedirs(target_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with zf.open(member) as source, open(target_path, "wb") as dest:
                        shutil.copyfileobj(source, dest)
                    extracted_files.append(target_path)
        
        return extracted_files
    
    def _extract_tar(self, tar_path: str, extract_dir: str, mode: str) -> List[str]:
        """Extract a TAR archive safely.
        
        Args:
            tar_path: Path to the TAR file.
            extract_dir: Directory to extract to.
            mode: TAR open mode.
            
        Returns:
            List of extracted file paths.
        """
        extracted_files = []
        
        with tarfile.open(tar_path, mode) as tf:
            for member in tf.getmembers():
                # Security check: prevent path traversal
                member_path = os.path.normpath(member.name)
                if member_path.startswith("..") or os.path.isabs(member_path):
                    continue
                
                target_path = os.path.join(extract_dir, member_path)
                
                # Ensure we don't extract outside the target directory
                real_extract_dir = os.path.realpath(extract_dir)
                real_target_path = os.path.realpath(target_path)
                
                if not real_target_path.startswith(real_extract_dir):
                    continue
                
                # Skip symlinks for security
                if member.issym() or member.islnk():
                    continue
                
                if member.isdir():
                    os.makedirs(target_path, exist_ok=True)
                elif member.isfile():
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with tf.extractfile(member) as source:
                        if source:
                            with open(target_path, "wb") as dest:
                                shutil.copyfileobj(source, dest)
                    extracted_files.append(target_path)
        
        return extracted_files
    
    def download_http(self, url: str, dest_dir: str) -> str:
        """Download a file from HTTP/HTTPS URL.
        
        Args:
            url: URL to download from.
            dest_dir: Directory to save the file.
            
        Returns:
            Path to the downloaded file.
        """
        import requests
        
        http_config = self.config.get("remote", {}).get("http", {})
        timeout = http_config.get("timeout_seconds", 60)
        max_retries = http_config.get("max_retries", 3)
        
        # Parse URL to get filename
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or "model"
        dest_path = os.path.join(dest_dir, filename)
        
        # Download with retries
        for attempt in range(max_retries):
            try:
                response = requests.get(url, stream=True, timeout=timeout)
                response.raise_for_status()
                
                # Check content length
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self.max_file_size:
                    raise ValueError(f"File too large: {int(content_length)} bytes")
                
                # Download
                with open(dest_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                return dest_path
                
            except requests.RequestException as e:
                if attempt == max_retries - 1:
                    raise RuntimeError(f"Failed to download {url}: {e}")
        
        raise RuntimeError(f"Failed to download {url} after {max_retries} attempts")
    
    def download_huggingface(self, model_id: str, dest_dir: str) -> str:
        """Download a model from HuggingFace Hub.
        
        Args:
            model_id: HuggingFace model identifier.
            dest_dir: Directory to save the model.
            
        Returns:
            Path to the downloaded model directory.
        """
        try:
            from huggingface_hub import snapshot_download
        except ImportError:
            raise ImportError("huggingface_hub is required for HuggingFace downloads")
        
        hf_config = self.config.get("remote", {}).get("huggingface", {})
        token_env_var = hf_config.get("token_env_var", "HF_TOKEN")
        token = os.environ.get(token_env_var)
        
        # Download the model
        local_dir = os.path.join(dest_dir, model_id.replace("/", "_"))
        
        snapshot_download(
            repo_id=model_id,
            local_dir=local_dir,
            token=token,
        )
        
        return local_dir
    
    def download_s3(self, s3_uri: str, dest_dir: str) -> str:
        """Download a file from S3.
        
        Args:
            s3_uri: S3 URI (s3://bucket/key).
            dest_dir: Directory to save the file.
            
        Returns:
            Path to the downloaded file.
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required for S3 downloads")
        
        # Parse S3 URI
        if not s3_uri.startswith("s3://"):
            raise ValueError(f"Invalid S3 URI: {s3_uri}")
        
        parts = s3_uri[5:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid S3 URI: {s3_uri}")
        
        bucket, key = parts
        filename = os.path.basename(key)
        dest_path = os.path.join(dest_dir, filename)
        
        # Download
        s3_client = boto3.client("s3")
        s3_client.download_file(bucket, key, dest_path)
        
        return dest_path
    
    def download_gcs(self, gcs_uri: str, dest_dir: str) -> str:
        """Download a file from Google Cloud Storage.
        
        Args:
            gcs_uri: GCS URI (gs://bucket/key).
            dest_dir: Directory to save the file.
            
        Returns:
            Path to the downloaded file.
        """
        try:
            from google.cloud import storage
        except ImportError:
            raise ImportError("google-cloud-storage is required for GCS downloads")
        
        # Parse GCS URI
        if not gcs_uri.startswith("gs://"):
            raise ValueError(f"Invalid GCS URI: {gcs_uri}")
        
        parts = gcs_uri[5:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid GCS URI: {gcs_uri}")
        
        bucket_name, blob_name = parts
        filename = os.path.basename(blob_name)
        dest_path = os.path.join(dest_dir, filename)
        
        # Download
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.download_to_filename(dest_path)
        
        return dest_path
