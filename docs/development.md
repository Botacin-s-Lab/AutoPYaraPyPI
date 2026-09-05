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

## Working on the Java backend

The clustering and rule-synthesis engine lives in a **separate repository**, [AutoPYaraBackend](https://github.com/Botacin-s-Lab/AutoPYaraBackend), and is embedded here as `autopyara/jars/AutoYara.jar`. See [Architecture](architecture.md) for how the two fit together.

```bash
git clone https://github.com/Botacin-s-Lab/AutoPYaraBackend.git
cd AutoPYaraBackend
mvn -B package                      # -> target/AutoYara-<version>.jar
```

To try a locally built backend, copy that jar over `autopyara/jars/AutoYara.jar` in your checkout of this package.

The backend releases independently, using the same commit-subject convention:

| Backend commit subject | Effect |
|---|---|
| `NewVersion` | Release with a minor bump (`1.0.5` → `1.1.0`) |
| `NewSubversion` | Release with a patch bump (`1.0.5` → `1.0.6`) |
| `pip sync` | Rebuild the jar and push it into this repository |

A `pip sync` commit updates **only** the jar here — it does not rebuild or re-publish the Python package. Cutting a new `autopyara` release afterwards is a separate, deliberate step.

## Contributing

`main` isn't open to direct pushes — every change, including from maintainers, goes through a pull request that's automatically built and tested, then reviewed. See [CONTRIBUTING.md](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/blob/main/CONTRIBUTING.md) in the repository for the full flow.
