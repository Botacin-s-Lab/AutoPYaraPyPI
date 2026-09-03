# AutoPYara
### Automated, Cluster-Driven YARA Rule Generation

[![PyPI version](https://img.shields.io/pypi/v/autopyara.svg)](https://pypi.org/project/autopyara/)
[![Python Versions](https://img.shields.io/pypi/pyversions/autopyara.svg)](https://pypi.org/project/autopyara/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/autopyara.svg)](https://pypi.org/project/autopyara/)

> Automatically discover malware families and generate high-quality, tightly scoped YARA rules using probabilistic clustering and Bloom-filtered n-gram analysis.

---

## 📌 Overview

**AutoPYara** is a Python framework for automated YARA rule generation from collections of malware samples.

It combines:

- Variational Bayesian Gaussian Mixture Models (VBGMM)
- Augmented DBSCAN with centroid refinement
- Malicious/benign Bloom filter isolation
- Byte-level n-gram feature extraction

The result: **cluster-aware, precision-engineered YARA signatures** with minimal manual effort.

---

## 🧠 Architecture

```text
Malware Samples
      │
      ▼
Byte n-gram Extraction
      │
      ▼
Bloom Filter Isolation
(benign removal + malicious focus)
      │
      ▼
Clustering Engine
(VBGMM or Augmented DBSCAN)
      │
      ▼
Cluster-Specific Signature Construction
      │
      ▼
High-Quality YARA Rules
```

## Features
* **Automated Clustering:** Group similar malware samples together automatically to create concise, targeted rules.
* **Two Core Presets:** Use the standard `AutoYara` (VBGMM) approach or the enhanced `AutoPYara` (Augmented DBSCAN) pipeline.
* **Built-in Bloom Filters:** Ships with pre-trained EMBER and AutoPYara bloom filters to efficiently filter out benign n-grams.
* **Multiple Output Formats:** Return rules as raw strings, compiled `yara-python` objects, or `yaramod` parsed objects.
* **Custom Training:** Train your own custom bloom filters on proprietary datasets.

---

## 🚀 Installation

### Requirements

* Python >= 3.8
* A **Java Runtime Environment (JRE 11+)** on `PATH` or pointed to by `JAVA_HOME`. AutoPYara's clustering/rule-generation backend runs inside a JVM. `pip install` itself doesn't need Java, but `AutoPYara()` will raise a clear error the first time you construct it without one — install a JRE before you actually use the tool. On Debian/Ubuntu: `sudo apt install default-jre`.

Install the package via pip:
```bash
pip install autopyara
```
or from a local build:
```bash
python -m build
pip install dist/autopyara-*.whl
```

**Note on first run:** to keep the initial install lightweight, the package needs about 600MB of pre-trained Bloom filter data that isn't bundled in the distribution. You don't need to fetch this manually — the first time you `import autopyara` and the data is missing, it's downloaded automatically from the [`data-branch`](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/tree/data-branch) branch of this repository. To trigger it explicitly (e.g. to pre-warm a Docker image), run:
```bash
autopyara-download
```


# Quick Start
Generating your first YARA rule is as simple as pointing the tool at a directory of malware samples.

```python
from autopyara import AutoPYara

# 1. Initialize the tool
tool = AutoPYara()

# 2. Generate a rule using the AutoPYara preset
results = tool.generate(
    input_files="/path/to/malware/directory",
    preset="AutoPYara",
    rule_name="my_custom_rule",
    output_format="string"
)

# 3. Print the results
print(f"Discovered {results['k_clusters']} distinct malware clusters.")
print("\nGenerated YARA Rule:")
print(results['rule_string'])
```



# ⚙️ Core Presets

AutoPYara abstracts complex clustering pipelines into easy-to-use presets via the `preset` argument in the `generate()` method.

---

## 1️⃣ `preset="AutoYara"` (Standard)

**Algorithm:** Variational Bayesian Gaussian Mixture Model (VBGMM)  

**Behavior:** Automatically infers the number of clusters ($K$) probabilistically.  

**Best For:** General-purpose rule generation where the structural diversity of the input directory is completely unknown.

---

## 2️⃣ `preset="AutoPYara"` (Enhanced)

**Algorithm:** Augmented DBSCAN combined with KMeans Soft Clustering  

**Behavior:** Uses a custom Augmented DBSCAN to calculate $K$ prior to centroid optimization.  

**Best For:** Producing more tightly bound rules for closely related malware families.

---

# 🛠 Advanced Usage

## Defining Custom $K$ Clusters

If you want to manually force the algorithm to split your samples into a specific number of clusters, you can override the presets:

```python
# Force exactly 4 clusters using the AutoPYara augmented pipeline
results = tool.generate(
    input_files="/path/to/malware",
    preset="AutoPYara",
    augmented_target_k=4  # Forces the optimizer to find 4 clusters
)
```

## Different Output Formats
By default, AutoPYara returns a raw string. However, you can integrate it directly into existing analysis pipelines by requesting Python objects:
```python
# Returns a compiled yara-python object ready for immediate scanning
results = tool.generate(
    input_files="/path/to/malware",
    output_format="yara-python"
)

compiled_rule = results["output"]
matches = compiled_rule.match("/path/to/suspicious/file.exe")
```

Supported formats: 'string', 'yara-python', and 'yaramod'.


## Using Custom Bloom Filters
The generate() function defaults to using the built-in "ember" bloom filters for both benign and malicious data. You can switch to the "autopyara" defaults, or provide absolute paths to your own retrained filters:

```python
results = tool.generate(
    input_files="/path/to/malware",
    bloom_malicious="/absolute/path/to/custom/malicious_bloom",
    bloom_benign="/absolute/path/to/custom/benign_bloom",
)
```


Training New Bloom Filters
You can train custom bloom filters on your own proprietary benign or malicious datasets using the train() method:

```python
tool = AutoPYara()

# Extract 8-grams from a directory of benign software
tool.train(
    input_dir="/path/to/benign/software",
    output_dir="/path/to/save/new/bloom",
    ngram_size=8
)
```


# 📚 API Reference: `generate()`

| Parameter | Type | Default | Description |
|------------|------|----------|-------------|
| `input_files` | `str` \| `list` | **Required** | Path to input directory or list of sample file paths. |
| `preset` | `str` | `None` | `'AutoYara'` or `'AutoPYara'`. Auto-configures the clustering pipeline. |
| `bloom_malicious` | `str` | `'ember'` | Built-in flag (`'ember'`, `'autopyara'`) or path to custom malicious Bloom filters. |
| `bloom_benign` | `str` | `'ember'` | Built-in flag (`'ember'`, `'autopyara'`) or path to custom benign Bloom filters. |
| `output_format` | `str` | `'string'` | `'string'`, `'yara-python'`, or `'yaramod'`. Determines output rule format. |
| `rule_name` | `str` | `'autoyara_rule'` | Base string used to name the generated rules. |
| `k_cluster` | `int` | `0` | Hardcode $K$ for VBGMM. Do **not** use with `preset="AutoPYara"`. |
| `augmented_target_k` | `int` | `None` | Hardcode target $K$ for the Augmented DBSCAN pipeline. |
| `verbose` | `bool` | `False` | Enable detailed logging during cluster generation. |

---

## 🧪 Development

```bash
pip install -e ".[test]"
pytest tests/
```

`tests/test_core_helpers.py` and `tests/test_augmented_dbscan.py` are pure-Python unit tests (no JVM/network needed). `tests/test_smoke_generate.py` runs the real pipeline end-to-end against small synthetic dummy files (not real malware) using the built-in bloom filters, so it needs a JRE and the bloom filter data to already be present.

See [RELEASING.md](RELEASING.md) for how versioning and PyPI publishing work.