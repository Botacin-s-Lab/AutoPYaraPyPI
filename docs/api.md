# API Reference

AutoPYara abstracts complex clustering pipelines into easy-to-use presets via the `preset` argument in the `generate()` method.

## Core presets

### `preset="AutoYara"` (Standard)

**Algorithm:** Variational Bayesian Gaussian Mixture Model (VBGMM)

**Behavior:** Automatically infers the number of clusters ($K$) probabilistically.

**Best for:** General-purpose rule generation where the structural diversity of the input directory is completely unknown.

### `preset="AutoPYara"` (Enhanced)

**Algorithm:** Augmented DBSCAN combined with KMeans soft clustering

**Behavior:** Uses a custom Augmented DBSCAN to calculate $K$ prior to centroid optimization.

**Best for:** Producing more tightly bound rules for closely related malware families.

## Advanced usage

### Defining a custom $K$

If you want to manually force the algorithm to split your samples into a specific number of clusters, you can override the presets:

```python
# Force exactly 4 clusters using the AutoPYara augmented pipeline
results = tool.generate(
    input_files="/path/to/malware",
    preset="AutoPYara",
    augmented_target_k=4  # Forces the optimizer to find 4 clusters
)
```

### Output formats

By default, AutoPYara returns a raw string. You can integrate it directly into existing analysis pipelines by requesting Python objects instead:

```python
# Returns a compiled yara-python object ready for immediate scanning
results = tool.generate(
    input_files="/path/to/malware",
    output_format="yara-python"
)

compiled_rule = results["output"]
matches = compiled_rule.match("/path/to/suspicious/file.exe")
```

Supported formats: `'string'`, `'yara-python'`, and `'yaramod'`.

### Custom Bloom filters

`generate()` defaults to the built-in `"ember"` Bloom filters for both benign and malicious data. You can switch to the `"autopyara"` defaults, or provide absolute paths to your own retrained filters:

```python
results = tool.generate(
    input_files="/path/to/malware",
    bloom_malicious="/absolute/path/to/custom/malicious_bloom",
    bloom_benign="/absolute/path/to/custom/benign_bloom",
)
```

### Training new Bloom filters

Train custom Bloom filters on your own proprietary benign or malicious datasets with `train()`:

```python
tool = AutoPYara()

# Extract 8-grams from a directory of benign software
tool.train(
    input_dir="/path/to/benign/software",
    output_dir="/path/to/save/new/bloom",
    ngram_size=8
)
```

## `generate()` parameters

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
