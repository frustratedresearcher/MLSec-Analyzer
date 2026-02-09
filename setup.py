"""Setup script for ML Model Security Analyzer."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip()
        for line in fh.readlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="ml-model-security-analyzer",
    version="1.0.0",
    author="Security Team",
    author_email="security@example.com",
    description="Static security analyzer for machine learning model files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/ml-model-security-analyzer",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "huggingface_hub>=0.20.0",
        "protobuf>=4.21.0",
        "h5py>=3.8.0",
        "numpy>=1.24.0",
        "jsonschema>=4.17.0",
    ],
    extras_require={
        "cloud": ["boto3>=1.28.0", "google-cloud-storage>=2.10.0"],
        "dev": ["pytest>=7.3.0", "pytest-cov>=4.1.0", "black>=23.0.0", "mypy>=1.4.0"],
    },
    entry_points={
        "console_scripts": [
            "mlsec-analyzer=mlsec_analyzer.cli:main",
        ],
    },
    keywords="security, machine-learning, vulnerability-scanner, ml-security, pickle, tensorflow, pytorch",
    project_urls={
        "Bug Reports": "https://github.com/example/ml-model-security-analyzer/issues",
        "Source": "https://github.com/example/ml-model-security-analyzer",
    },
)
