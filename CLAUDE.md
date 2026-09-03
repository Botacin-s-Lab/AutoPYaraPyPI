# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AutoPYara is a Python package that wraps a Java backend (`AutoYara.jar`, loaded via `jpype`) to cluster malware samples and generate YARA rules. The Python layer handles I/O, bloom-filter path resolution, an alternative (pure-Python) clustering path, and output formatting; the actual candidate-set/feature/rule-building work happens inside the JVM.

## Build / install / run

No linter is configured. There's no `pyproject.toml`; `setup.py` is the sole build config (`python -m build` still works against it via setuptools' legacy backend).

Install locally for development:
```bash
pip install -e ".[test]"
```

Build the distributables (sdist + wheel, writes to `dist/`):
```bash
python -m build
```

Run the test suite:
```bash
pytest tests/
```
- `tests/test_core_helpers.py`, `tests/test_augmented_dbscan.py` — pure-Python, no JVM/network/data needed.
- `tests/test_smoke_generate.py` — real end-to-end run (real JVM, real bloom filters) against small synthetic dummy files generated at test time (not real malware); needs Java and the bloom data already present.

Manually trigger the bloom-filter data download (normally auto-runs on first `import autopyara` if `autopyara/data/blooms` is missing; set `AUTOPYARA_SKIP_AUTO_DOWNLOAD=1` to suppress the auto-download, e.g. in tests that only need the pure-Python helpers):
```bash
autopyara-download
```

Requires a JRE (11+) on `PATH` or `JAVA_HOME` set to actually run — checked once, at first `AutoPYara()` construction, by `PythonInterface._check_java_installed()` in [autopyara/interface.py](autopyara/interface.py), which raises a clear `RuntimeError` if neither is found. This is **not** checked at `pip install` time (see "No install-time Java gate" below) — there's no way to exercise `core.py`'s Java-backed paths without a working JVM + jar, though `resolve_bloom_path`/`sanitize_rule_name` (see Architecture) are plain functions that don't need one.

Quick manual smoke test:
```python
from autopyara import AutoPYara
tool = AutoPYara()
results = tool.generate(input_files="/path/to/samples", preset="AutoPYara", output_format="string")
print(results["rule_string"])
```

### Release automation

[.github/workflows/release.yml](.github/workflows/release.yml) triggers on push to `main` whose commit message contains "New version" (case-insensitive): runs the test matrix (Python 3.8–3.11, installing the built **wheel** and running the full `tests/` suite against a real JVM — this is the actual pre-publish functional gate), then — only if that passes on every version — auto-bumps the patch version in `setup.py` via [.github/scripts/bump_version.py](.github/scripts/bump_version.py), commits, tags `vX.Y.Z`, builds sdist + wheel, and publishes both to PyPI with `PYPI_API_TOKEN`. Full details, including one-time repo setup, in [RELEASING.md](RELEASING.md) — read that before touching the workflow or `setup.py`'s version-parsing assumptions.

## Architecture

**Two-language pipeline.** `autopyara/interface.py`'s `PythonInterface` is a mixin that starts a single class-level JVM (`jpype.startJVM`, `-Djava.class.path=<pkg>/jars/AutoYara.jar`) and provides `convert_java_to_python()` to recursively unwrap Java collections/boxed types into native Python. `core.py`'s `AutoPYara` class extends it and holds handles to the Java classes it drives: `AutoYaraCluster` (legacy), `AutoYaraPython` (the one actually used), and `Bytes2Bloom` (training).

**`generate()` in [autopyara/core.py](autopyara/core.py) is the single entry point** and does, in order:
1. Preset expansion — `preset="AutoYara"` sets `cluster_alg='VBGMM'` (K inferred by the Java VBGMM); `preset="AutoPYara"` sets `cluster_alg='AugmentedKMeansDBSCANSoft'`, which requires K to be computed in Python first (see below).
2. Bloom path resolution — `bloom_malicious`/`bloom_benign` accept the strings `'ember'` or `'autopyara'` (mapped to subdirs under `autopyara/data/blooms/`) or an absolute path to a custom filter set.
3. Marshal `input_files` into a Java `ArrayList<File>` and set fields directly on the `self.yara_cluster` Java object (this codebase configures the Java object via public field assignment, not constructor args or a builder).
4. Call `findBestRulePipelineInit()`, then for any algorithm in `augmented_algorithms` (the `AugmentedKMeans*` variants), pull `self.yara_cluster.targets` (candidate file paths) back into Python, run `AugmentedDBScan` (pure Python/sklearn — see below) to produce `predictor_labels` and a derived K, and push both back onto the Java object before the real run (`pythonRun()`). This split exists because the augmented clustering (ssdeep + DBSCAN) is implemented in Python, but rule synthesis from the resulting clusters is still done in Java.
5. Call `pythonRun()` (stdout/stderr optionally suppressed via the `suppress_output` context manager unless `verbose=True`), convert the Java result map back to Python, rename the generated rule using `rule_name` (regex substitution on `rule <N>`), and produce `output` in the requested `output_format` (`'string'` raw, `'yara-python'` via `yara.compile`, `'yaramod'` via `yaramod.parse_string`).
6. Always calls `resetYaraState()` and `reset_memory()` (Python `gc.collect()` + `System.gc()`) in a `finally`-equivalent path on both success and exception, because the JVM state is one shared mutable object reused across calls.

**`autopyara/augmented_predictor/DBSCAN_SSDEEP.py`** (`AugmentedDBScan`) implements the "AutoPYara" preset's clustering: it fuzzy-hashes each file with `ppdeep` (ssdeep-compatible), builds a pairwise similarity/distance matrix, and runs `sklearn.cluster.DBSCAN` with `metric="precomputed"`. When `augmented_target_k` is given instead of a raw similarity threshold, `predict()` does a simple iterative search (adjusting the similarity threshold up/down based on whether the resulting cluster count is above/below target) rather than a closed-form solve — read this loop before changing the threshold-adjustment direction, since it's easy to get the sign backwards (higher similarity threshold → more/smaller clusters, not fewer).

**Pure-Python helpers.** `resolve_bloom_path()` and `sanitize_rule_name()` are module-level functions in [autopyara/core.py](autopyara/core.py) (deliberately pulled out of `generate()`'s body) so they're unit-testable without a JVM — see `tests/test_core_helpers.py`. If you touch `generate()`'s bloom-flag or rule-name logic, edit these functions, not inline code inside `generate()`.

**Data files.** `autopyara/data/blooms/{ember,autopyara}/{benign,malicious}/*.bloom` are pre-trained bloom filters excluded from git (see `.gitignore`: `autopyara/data/*`) and fetched lazily instead. `autopyara/__init__.py` checks for `autopyara/data/blooms` at import time and, if absent (and `AUTOPYARA_SKIP_AUTO_DOWNLOAD` isn't set), calls `download.download_and_extract()` automatically (also exposed as the `autopyara-download` console script from `setup.py`). `download.py` pulls a branch-archive zip from the `data-branch` branch of this same GitHub repo (`Botacin-s-Lab/AutoPYaraPyPI`, overridable via `AUTOPYARA_DATA_REPO`/`AUTOPYARA_DATA_BRANCH` env vars) — that branch's `data/blooms/...` layout must stay in sync with what `resolve_bloom_path()` expects (`data/blooms/{ember,autopyara}/{benign,malicious}/`).

**No install-time Java gate, deliberately.** `setup.py` has no Java check — `pip install autopyara` should succeed regardless of whether the target machine has a JRE (e.g. building a Docker image that only runs the tool elsewhere). The only Java check is the runtime one in `interface.py` (see above). The real "does this actually work" gate is CI's `tests/test_smoke_generate.py`, which runs a full JVM pipeline against the exact wheel about to be published, before every release — see [RELEASING.md](RELEASING.md).

**Presets vs. manual config.** `generate()` exposes the full underlying parameter surface (`bicluster_alg`, `cluster_alg`, `selection_heuristic`, `bicluster_feature_prune_coverage`, `k_cluster`, `similarity_threshold`, `augmented_target_k`) for advanced use, but `preset` overwrites `bicluster_alg`/`cluster_alg`/`bicluster_feature_prune_coverage`/`selection_heuristic` unconditionally when set. `k_cluster` (manual K for VBGMM) and the augmented-K auto-calculation are mutually exclusive — passing both raises `ValueError`.
