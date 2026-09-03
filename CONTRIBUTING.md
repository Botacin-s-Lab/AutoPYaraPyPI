# Contributing

Contributions are welcome — if you find a bug, have a fix, or want to add something, we're happy to take a look.

## How to contribute

1. **Fork** the repository and create a branch off `main` for your change.
2. Make your change. If it touches Python code, add or update tests under `tests/` where it makes sense (see [Development & Releasing](https://botacin-s-lab.github.io/AutoPYaraPyPI/development/) for how to run them locally).
3. **Open a pull request** against `main`.
4. GitHub Actions will automatically build the package and run the full test suite against your PR — you'll see the results as checks on the PR.
5. Once the checks pass and a maintainer approves the change, it gets merged.

`main` only accepts changes through this PR flow — nobody, including maintainers, pushes to it directly (the one exception is the automated version-bump commit the release pipeline makes after a maintainer explicitly triggers a release; see [RELEASING.md](RELEASING.md)).

## Reporting issues

Found a bug or have a feature request? [Open an issue](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/issues) — include enough detail to reproduce (Python version, OS, and a minimal example if you can).

## Questions

For anything else, reach out to the maintainer — see the contact at the bottom of the [README](README.md).
