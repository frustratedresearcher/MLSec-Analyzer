# mlsec-analyzer

Static security analyzer for ML model files. Finds vulnerabilities in pickle, Keras, GGUF, TensorFlow, and other model formats before they reach production.

## Why?

ML models are code. Pickle files execute arbitrary Python on load. Keras Lambda layers run code during inference. GGUF files can crash parsers with crafted headers. This tool catches these issues.

## Install

```bash
pip install -e .

# optional extras
pip install -e ".[modelscan]"   # ProtectAI's scanner
pip install -e ".[secrets]"     # secret detection
pip install -e ".[all]"         # everything
```

## Usage

```bash
# scan a file
mlsec-analyzer scan model.pkl

# scan a directory
mlsec-analyzer scan ./models -o report.json

# scan from huggingface
mlsec-analyzer scan --huggingface bert-base-uncased

# generate exploit test files
mlsec-analyzer generate-testcases gguf -o ./testcases
mlsec-analyzer generate-testcases pickle
mlsec-analyzer generate-testcases keras

# create PoCs from scan results
mlsec-analyzer generate-poc report.json -o ./pocs
```

## What it finds

| Category | Severity | Examples |
|----------|----------|----------|
| Pickle RCE | Critical | `os.system`, `subprocess`, `eval` in pickle |
| Keras Lambda | Critical | Code execution via Lambda layers (CVE-2024-3660) |
| GGUF exploits | Critical | Integer overflow, SSTI, dimension overflow |
| Zip Slip | High | Path traversal in archives |
| Secrets | Critical | API keys, tokens, credentials |
| Backdoors | High | Anomalous weight distributions |

## Supported formats

- **Pickle**: `.pkl`, `.pth`, `.pt`, `.bin`, `.joblib`
- **Keras**: `.h5`, `.keras`, `.hdf5`
- **TensorFlow**: `.pb`, SavedModel dirs
- **GGUF**: `.gguf`, `.ggml`
- **NumPy**: `.npy`, `.npz`
- **ONNX**: `.onnx`
- **SafeTensors**: `.safetensors`

## Test case generation

Generate malicious model files for security testing:

```bash
# list available formats
mlsec-analyzer list-formats

# generate all GGUF exploits (10 types)
mlsec-analyzer generate-testcases gguf

# generate all pickle exploits (10 types)  
mlsec-analyzer generate-testcases pickle

# generate keras exploits (12 types)
mlsec-analyzer generate-testcases keras

# specific vulnerability only
mlsec-analyzer generate-testcases gguf -t jinja2_ssti
```

Output includes:
- Actual malicious files with real exploit payloads
- `manifest.json` describing each file
- CVE references where applicable

## CI/CD

```yaml
# GitHub Actions
- name: Scan models
  run: |
    pip install mlsec-analyzer
    mlsec-analyzer scan ./models --fail-on-critical -o results.sarif

- name: Upload results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Exit codes: `0` = clean, `1` = vulns found, `2` = error

## As a library

```python
import mlsec_analyzer

result = mlsec_analyzer.scan("model.pkl")

for vuln in result.vulnerabilities:
    print(f"[{vuln.severity.level}] {vuln.vulnerability_type}")
```

## Credits

Built on:
- [Fickling](https://github.com/trailofbits/fickling) - pickle analysis (Trail of Bits)
- [ModelScan](https://github.com/protectai/modelscan) - model scanning (ProtectAI)
- [GuardDog](https://github.com/DataDog/guarddog) - package scanning (DataDog)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - secret detection (Truffle Security)

CVEs covered: CVE-2024-3660, CVE-2024-21802, CVE-2024-21836, CVE-2024-34359

## License

MIT
