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

See the [API Reference](api.md) for the two built-in presets, advanced usage (custom cluster counts, output formats, custom Bloom filters, training your own filters), and the full parameter table for `generate()`.
