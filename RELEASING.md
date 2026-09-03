# Releasing

Publishing to PyPI is automated by [.github/workflows/release.yml](.github/workflows/release.yml). This document covers the one-time setup it needs and how the flow works day to day.

## One-time setup (do this before the first automated release)

1. **Create a PyPI API token** and add it to this repo as a GitHub Actions secret named `PYPI_API_TOKEN`.
   - `autopyara` has not been published yet, so the token must be scoped to your **entire PyPI account** (an existing-project-scoped token isn't possible until after the first upload). Once the first release lands, you can go back and re-scope/replace it with a project-scoped token for `autopyara` if you'd rather not keep an account-wide token around.
   - Add it at: repo **Settings → Secrets and variables → Actions → New repository secret**, name `PYPI_API_TOKEN`.
2. **Confirm `main` allows the release workflow to push directly to it.** The `release` job commits a version bump and pushes a tag straight to `main` using the default `GITHUB_TOKEN`. If branch protection on `main` requires pull requests or blocks the `github-actions[bot]` actor, that push will fail — either relax the rule for this workflow, or add an exception allowing the Actions bot (or a PAT with bypass rights) to push.
3. That's it — no PyPI "trusted publisher" registration is needed since this uses a token, not OIDC.

## How a release happens

1. Make whatever code changes you want on `main` as normal.
2. When you're ready to cut a release, make a commit whose message contains the phrase **"New version"** (case-insensitive, anywhere in the message) and push it to `main`.
3. GitHub Actions then runs, in order:
   - **`gate`** — checks the head commit message for "New version". Everything below only runs if it matches.
   - **`test`** — across Python 3.9–3.12: builds the sdist + wheel, installs the wheel (the same artifact a real `pip install autopyara` would fetch), restores/downloads the bloom filter data, and runs the full test suite (`tests/`) — including `tests/test_smoke_generate.py`, which runs the real pipeline end-to-end against a real JVM. This is the actual "does this release work" check; a failure here stops the release and nothing gets published.
   - **`release`** (only if `test` passed on every Python version) — bumps the **patch** version in `setup.py` (e.g. `0.1.3` → `0.1.4`), commits that as `Release vX.Y.Z [automated]`, tags it `vX.Y.Z`, pushes both to `main`, builds the sdist + wheel from the bumped code, runs `twine check`, uploads both to PyPI, and creates a GitHub Release with both attached and auto-generated notes.

You never need to hand-edit the version number yourself — every "New version" commit bumps the patch version by exactly one. If you need a minor or major bump, edit `version="X.Y.Z"` in [setup.py](setup.py) yourself in a **separate, prior** commit (one that does *not* contain "New version"), then make your actual "New version" commit — the automated bump always increments whatever is currently in `setup.py`.

## Where the Java requirement is checked

AutoPYara needs a JRE (11+) to actually run (its backend is a JVM process — see `autopyara/interface.py`'s `PythonInterface._check_java_installed()`, which raises a clear error the first time `AutoPYara()` is constructed without one). That check deliberately does **not** run at `pip install` time — `setup.py` has no Java gate, and the package ships both a wheel and an sdist, so most installs never execute `setup.py` at all. Blocking install on Java would be inconsistent (wheel installs would bypass it anyway) and would get in the way of installing the package somewhere it'll only run later (e.g. building a Docker image on a Java-less host).

Instead, real functional correctness — a full JVM run against the exact wheel that's about to be published — is what `tests/test_smoke_generate.py` verifies in the `test` job, before `release` is ever allowed to run. That's the actual pre-publish gate.

## Where the bloom filter data comes from

`autopyara/data/blooms/` (~600MB, gitignored, not shipped in the sdist) is fetched at first `import autopyara` — or on demand via the `autopyara-download` console script — from the [`data-branch`](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/tree/data-branch) branch of this same repository (see [autopyara/download.py](autopyara/download.py)). To update the shipped bloom filters, push new data to `data-branch` in the same `data/blooms/{ember,autopyara}/{benign,malicious}/*.bloom` layout — no code change needed, and no version bump is required for the data itself to change (existing installs re-download whenever their local `autopyara/data/blooms` directory is missing).
