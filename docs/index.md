---
title: AutoPYara — Automated YARA Rule Generation
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

![AutoPYara](images/favicon.svg){ .hero-logo }

# AutoPYara

<p class="tagline">Automated, Cluster-Driven YARA Rule Generation</p>

[Get Started :material-arrow-right:](installation.md){ .md-button .md-button--primary }
[View on GitHub :fontawesome-brands-github:](https://github.com/Botacin-s-Lab/AutoPYaraPyPI){ .md-button }
[PyPI :fontawesome-brands-python:](https://pypi.org/project/autopyara/){ .md-button }

</div>

AutoPYara is a Python framework for automated YARA rule generation from collections of malware samples. It combines:

- Variational Bayesian Gaussian Mixture Models (VBGMM)
- Augmented DBSCAN with centroid refinement
- Malicious/benign Bloom filter isolation
- Byte-level n-gram feature extraction

The result: cluster-aware, precision-engineered YARA signatures with minimal manual effort.

!!! info "This site is a work in progress"
    This documentation is intentionally basic for now — installation, a quick start, and the full API reference. More material (including the accompanying paper, once published) will land here over time.

AutoPYara is [live on PyPI](https://pypi.org/project/autopyara/) — `pip install autopyara` to get started.

## How it works

```mermaid
flowchart TD
    A[Malware Samples] --> B[Byte n-gram Extraction]
    B --> C["Bloom Filter Isolation<br/>(benign removal + malicious focus)"]
    C --> D["Clustering Engine<br/>(VBGMM or Augmented DBSCAN)"]
    D --> E[Cluster-Specific Signature Construction]
    E --> F[High-Quality YARA Rules]
```

## Features

<div class="feature-grid" markdown>

<div markdown>
### :material-cog-sync: Automated clustering
Group similar malware samples together automatically to create concise, targeted rules.
</div>

<div markdown>
### :material-swap-horizontal: Two core presets
The standard `AutoYara` (VBGMM) approach, or the enhanced `AutoPYara` (Augmented DBSCAN) pipeline.
</div>

<div markdown>
### :material-filter-variant: Built-in Bloom filters
Ships with pre-trained EMBER and AutoPYara filters to efficiently filter out benign n-grams.
</div>

<div markdown>
### :material-file-export: Multiple output formats
Raw strings, compiled `yara-python` objects, or `yaramod` parsed objects.
</div>

<div markdown>
### :material-school: Custom training
Train your own Bloom filters on proprietary datasets.
</div>

</div>

## Where to go next

- [Installation](installation.md) — requirements and how to install AutoPYara.
- [Quick Start](quickstart.md) — generate your first YARA rule.
- [API Reference](api.md) — presets, advanced usage, and the full `generate()` parameter table.
- [Development & Releasing](development.md) — running the tests and how releases are published.
