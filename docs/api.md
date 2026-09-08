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

If you want to steer the algorithm toward a specific number of clusters, you can override the presets:

```python
# Aim for 4 clusters using the AutoPYara augmented pipeline
results = tool.generate(
    input_files="/path/to/malware",
    preset="AutoPYara",
    augmented_target_k=4  # A target, not a guarantee -- see below
)

print(results["k_clusters"])  # what you actually got
```

!!! warning "`augmented_target_k` is a target, not a guarantee"
    The augmented pipeline does not solve for $K$ directly. It runs a **bounded
    search** over the ssdeep similarity threshold, re-clustering at each step and
    keeping whichever threshold landed closest to your target:

    - at most **20 iterations**, stopping early once the count is within `0.5` of the target
    - the step size decays as `15 / (iteration + 1)`, so late iterations barely move
    - the threshold is clamped to `[1, 99]`

    If no threshold reaches the target, the search does **not** fail — it returns
    the closest result it found. Two properties of the underlying clustering make
    an exact hit impossible for some inputs:

    - DBSCAN over fuzzy-hash distances is **discrete**. Cluster count jumps as the
      threshold sweeps, so many values of $K$ are simply unreachable for a given
      corpus.
    - Samples DBSCAN marks as **noise** each receive their own ascending cluster
      ID, and those count toward $K$.

    Always read back `results["k_clusters"]` rather than assuming you got what you
    asked for. The same number is reported during the run on the console line
    `[*] Final Opt: Threshold=..., K=...`.

### Output formats

!!! info "`generate()` always returns a `dict`"
    `output_format` controls only what `results["output"]` holds. The raw rule
    text is available as `results["rule_string"]` in **every** mode, alongside
    metadata such as `k_clusters`, `file_count` and `gram_size`.

| `output_format` | Type of `results["output"]` | Use it for |
|---|---|---|
| `'string'` (default) | `str` | Writing a `.yar` file, logging, diffing |
| `'yara-python'` | `yara.Rules` | Scanning files immediately |
| `'yaramod'` | `yaramod.YaraFile` | Inspecting or rewriting rule structure |

#### `'string'`

```python
results = tool.generate(input_files="/path/to/malware")
print(results["output"])
```

```
rule autoyara_rule_0
{
	//Input TP Rate:
	//6/6
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 4D 5A 90 00 03 00 00 00 }
		$x1 = { 50 45 00 00 4C 01 03 00 }
	condition:
		1 of ($x*)
}
```

In this mode `results["output"]` and `results["rule_string"]` are the same string.

#### `'yara-python'`

Returns a **compiled** `yara.Rules` object, ready to scan without a separate
`yara.compile()` step:

```python
results = tool.generate(
    input_files="/path/to/malware",
    output_format="yara-python"
)

compiled = results["output"]                           # yara.Rules
matches = compiled.match("/path/to/suspicious.exe")    # list[yara.Match]

for m in matches:
    print(m.rule)                                      # 'autoyara_rule_0'
    for sm in m.strings:                               # list[StringMatch]
        inst = sm.instances[0]
        print(" ", sm.identifier, inst.offset, bytes(inst.matched_data))
```

```
autoyara_rule_0
  $x0 0 b'MZ\x90\x00\x03\x00\x00\x00'
```

#### `'yaramod'`

Returns a parsed `yaramod.YaraFile`, giving structured access to the rule rather
than its text:

```python
results = tool.generate(
    input_files="/path/to/malware",
    output_format="yaramod"
)

yara_file = results["output"]                  # yaramod.YaraFile
rule = yara_file.rules[0]                      # yaramod.Rule

print(rule.name)                               # 'autoyara_rule_0'
print(rule.condition.text)                     # '1 of ($x*)'
print([s.identifier for s in rule.strings])    # ['$x0', '$x1']
```

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
| `augmented_target_k` | `int` | `None` | Target $K$ for the Augmented DBSCAN pipeline. Best-effort, not guaranteed &mdash; check `results["k_clusters"]`. |
| `verbose` | `bool` | `False` | Enable detailed logging during cluster generation. |
