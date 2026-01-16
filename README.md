# AutoPYaraPyPI

Here is the complete, comprehensive README.md file content. You can copy the code block below and save it directly as README.md in your repository.

Markdown
# AutoPYara: Enhanced Malware YARA Rule Generation

**AutoPYara** is a Python-based wrapper and enhancement suite for the Java *AutoYara* library. It bridges the gap between high-performance Java Bloom filter processing and Python's modern data science ecosystem.

This tool automates the creation of YARA rules for malware detection by clustering samples based on shared n-grams and generating signatures that match malicious patterns while avoiding benign ones.

## 🌟 New Features in This Release

### 1. Smart Flag System
No longer manage complex file paths for standard filters. AutoPYara now includes a smart resolution system:
* **`"ember"`**: Automatically points to the high-quality EMBER dataset filters included in the package.
* **`"autopyara"`**: Automatically points to the lightweight default filters.
* **Custom Path**: If you provide a raw path (e.g., `/opt/my_filters`), the tool uses it directly.

### 2. Augmented Clustering (SSDEEP + DBSCAN)
Integrated **Augmented Clustering** logic that removes the need to guess the number of clusters (`k`):
* Uses **SSDEEP** (via `ppdeep`) to fuzzy-hash malware samples.
* Uses **DBSCAN** to group samples based on structural similarity.
* Automatically calculates the optimal `k` for YARA rule generation.

### 3. Production-Ready Python API
* Fully pip-installable (`pip install .`).
* Resolves JVM memory issues and path dependencies automatically.
* Outputs rules in multiple formats: **Raw String**, **Compiled YARA**, or **YARA-Mod AST**.

---

## 📦 Installation

### Prerequisites
* **Python 3.10+** (Recommended)
* **Java Runtime Environment (JRE) 8+**
* **Conda** (Recommended for environment management)

### Step 1: Clone and Setup Environment
```bash
# 1. Create a fresh environment
conda create -n autopyara_env python=3.10 -y
conda activate autopyara_env

# 2. Install dependencies
conda install numpy scipy scikit-learn pandas -y
pip install yara-python yaramod jpype1 requests ppdeep

# 3. Clone repository
git clone [https://github.com/YourOrg/AutoPYara.git](https://github.com/YourOrg/AutoPYara.git)
cd AutoPYara
Step 2: Install Package
You can install in Editable Mode (for development) or as a Wheel (for production).

Option A: Developer Install (Recommended)

Bash
pip install -e .
Option B: Production Build

Bash
pip install wheel setuptools
python setup.py sdist bdist_wheel
pip install dist/AutoPYara-*.whl
🚀 Usage Guide
1. Basic Generation (Using Smart Flags)
The easiest way to generate rules is to use the built-in dataset flags.

Python
from autopyara import AutoPYara

# Initialize the tool
tool = AutoPYara(ngram_top_k=500)

input_files = ["/malware/sample1.exe", "/malware/sample2.exe"]

# Generate Rule using 'ember' filters
result = tool.generate(
    input_files=input_files,
    bloom_malicious="ember",        # <--- Smart Flag
    bloom_benign="ember",           # <--- Smart Flag
    bicluster_alg="SpectralCoCluster",
    cluster_alg="VBGMM",            # Standard Clustering
    output_format="string",
    rule_name="MyMalwareRule",
    verbose=True
)

print(result['output'])
2. Advanced: Augmented Clustering (Auto-K)
If you don't know how many variations of the malware exist, use AugmentedKMeansDBSCAN. This will use SSDEEP similarity to decide k for you.

Python
result = tool.generate(
    input_files=input_files,
    bloom_malicious="ember",
    bloom_benign="ember",
    cluster_alg="AugmentedKMeansDBSCAN", # <--- Auto-K Algorithm
    similarity_threshold=80,             # DBSCAN similarity %
    output_format="string",
    rule_name="AutoK_Rule"
)

print(f"Automatically determined K: {result['k_clusters']}")
print(result['output'])
⚙️ Configuration Reference
AutoPYara(ngram_top_k=1000)
ngram_top_k: Number of frequent n-grams to keep. Higher = more specific rules, but slower.

generate(...) Options
Parameter	Type	Description
input_files	list or str	List of file paths or path to a directory.
bloom_malicious	str	"ember", "autopyara", or path to custom Bloom filters.
bloom_benign	str	Same as above.
cluster_alg	str	VBGMM (Default), KMeans, AugmentedKMeansDBSCAN, AugmentedKMeansVT.
k_cluster	int	Manual cluster count (Ignored for Augmented algs).
output_format	str	string, yara-python (compiled object), yaramod (AST).
verbose	bool	Enable debug logs from Java backend.
🧪 Testing
The repository includes a comprehensive test suite (test4.py or similar) to verify that Smart Flags and Augmented Prediction are working.

Bash
# Run the test suite
python tests/test_smart_config.py
Note: Ensure you have unittest installed.

🔧 Troubleshooting
1. ResourceWarning: unclosed file (ppdeep)

Cause: Older versions of ppdeep do not close file handles.

Fix: We have patched autopyara/augmented_predictor/DBSCAN_SSDEEP.py to manually handle file opening/closing. Ensure you are using the latest version of this package.

2. JVM Heap Space Errors

Cause: Processing gigabytes of malware with small heap.

Fix: Modify interface.py:

Python
jpype.startJVM(..., "-Xmx4096m") # Increase to 4GB or more
3. "Flag 'ember' not found"

Cause: The data/blooms/ember directory is missing from the package.

Fix: Ensure MANIFEST.in includes recursive-include autopyara/data * and rebuild the package.

📄 License
[Insert License Here] - Based on original AutoYara research.