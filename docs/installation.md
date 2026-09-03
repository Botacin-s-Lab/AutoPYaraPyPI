# Installation

## Requirements

- Python >= 3.9
- A **Java Runtime Environment (JRE 11+)** on `PATH` or pointed to by `JAVA_HOME`. AutoPYara's clustering/rule-generation backend runs inside a JVM. `pip install` itself doesn't need Java, but constructing `AutoPYara()` will raise a clear error the first time you do so without one — install a JRE before you actually use the tool.

    On Debian/Ubuntu:

    ```bash
    sudo apt install default-jre
    ```

## Install from PyPI

```bash
pip install autopyara
```

## Install from a local build

```bash
python -m build
pip install dist/autopyara-*.whl
```

## First run: the Bloom filter data

To keep the initial install lightweight, the package needs about 600MB of pre-trained Bloom filter data that isn't bundled in the distribution. You don't need to fetch this manually — the first time you `import autopyara` and the data is missing, it's downloaded automatically from the [`data-branch`](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/tree/data-branch) branch of the repository.

To trigger the download explicitly (for example, to pre-warm a Docker image):

```bash
autopyara-download
```
