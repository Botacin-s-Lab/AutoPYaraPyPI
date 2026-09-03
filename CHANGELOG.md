# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.2] - 2026-09-03

### Fixed
- PyPI package metadata: added `license`, `classifiers` (Python 3.9–3.12, MIT, development status), and `project_urls` (GitHub, docs site, issue tracker, changelog) to `setup.py`. Previously the PyPI page showed `License: None` and an empty classifier list, which broke the README's Python-versions badge.

### Added
- Documentation site at [botacin-s-lab.github.io/AutoPYaraPyPI](https://botacin-s-lab.github.io/AutoPYaraPyPI/), built with MkDocs Material.
- Branch protection on `main`: pull requests with review required for everyone, enforced via a GitHub Ruleset; the release automation bypasses it using a dedicated `RELEASE_PAT`.
- `CONTRIBUTING.md` and automated PR testing (`pr-checks.yml`) — every PR against `main` now runs the full build+install+test suite.
- Two-tier release triggers: a commit subject containing "New subversion" cuts a patch release, "New version" cuts a minor release; both run the full test matrix before publishing.
- This changelog.

## [0.1.1] - 2026-09-03

### Added
- First public release on PyPI.
- Bloom filter data is now downloaded from this repository's `data-branch` branch (previously an anonymous peer-review mirror).
