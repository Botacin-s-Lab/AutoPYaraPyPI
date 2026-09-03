# Development & Releasing

## Running the tests

```bash
pip install -e ".[test]"
pytest tests/
```

- `tests/test_core_helpers.py` and `tests/test_augmented_dbscan.py` are pure-Python unit tests — no JVM, network, or Bloom filter data needed.
- `tests/test_smoke_generate.py` runs the real pipeline end-to-end against small synthetic dummy files (never real malware), using the built-in Bloom filters. It needs a JRE and the Bloom filter data to already be present.

## Building locally

```bash
python -m build
```

Produces both a wheel and an sdist under `dist/`.

## How releases are published

Publishing to PyPI is fully automated: pushing a commit to `main` whose **subject line** contains a trigger phrase runs the full test matrix, and only if it passes does it bump the version, tag, build, and publish.

- **"New subversion"** → patch bump (`0.1.5` → `0.1.6`)
- **"New version"** → minor bump (`0.1.5` → `0.2.0`)

See [RELEASING.md](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/blob/main/RELEASING.md) in the repository for the full runbook.
