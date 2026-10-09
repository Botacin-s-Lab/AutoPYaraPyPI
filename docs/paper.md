---
title: Paper & Resources — AutoPYara
---

# Paper & Resources

!!! success "Accepted at ACSAC 2026"
    **AutoPYara: Next-Gen YARA Rule Generator for Malware Family Clustering** will appear at the *Annual Computer Security Applications Conference (ACSAC), 2026*.

[Download the paper (PDF) :material-file-pdf-box:](paper/AutoPYara_ACSAC2026.pdf){ .md-button .md-button--primary }
[ACSAC artifact (Zenodo) :material-archive:](https://zenodo.org/records/23107801){ .md-button }

Mabon Ninan\*, Nhat Minh Nguyen\*, Soumyajyoti Dutta, Sidharth Anil, and Marcus Botacin — Texas A&M University. \*Equal contribution.

## Abstract

Millions of malware variants threaten users daily, such that clustering these samples is key for fast incident response. AutoYara is the current state-of-the-art for automatic YARA rule generation, but the task remains challenging on realistic datasets, where intra-family diversity and noisy clustering can degrade rule quality. We present AutoPYara, a solution armored with: (1) precise cluster centroid selection based on similarity hashing, and (2) an improved heuristic for estimating subclusters within a malware family using historical VirusTotal data. We implement AutoPYara as an open-source Python package, `pip install autopyara`, to support reproducibility and practical use. We show that AutoPYara, (1) increases rule coverage by 14 percentage points; (2) reduces variance by 7.1 percentage points, comparing the average variance AutoPYara exhibits to that of AutoYara; and (3) improves threat-hunting accuracy by 10%. AutoPYara produces robust and effective YARA rules than prior automatic approaches in practical settings.

## Citation

Recommended citation:

> M. Ninan, N. M. Nguyen, S. Dutta, S. Anil, and M. Botacin, "AutoPYara: Next-Gen YARA Rule Generator for Malware Family Clustering," *Annual Computer Security Applications Conference (ACSAC)*, 2026.

```bibtex
@inproceedings{autopyara2026,
  title     = {AutoPYara: Next-Gen YARA Rule Generator for Malware Family Clustering},
  author    = {Ninan, Mabon and Nguyen, Nhat Minh and Dutta, Soumyajyoti and Anil, Sidharth and Botacin, Marcus},
  booktitle = {Annual Computer Security Applications Conference (ACSAC)},
  year      = {2026}
}
```

## Artifacts and resources

| Resource | Host | Link |
|---|---|---|
| :material-archive: **ACSAC permanent artifact** | Zenodo | [zenodo.org/records/23107801](https://zenodo.org/records/23107801) |
| :fontawesome-brands-github: **ACSAC artifact source** | GitHub | [Botacin-s-Lab/AutoPYara](https://github.com/Botacin-s-Lab/AutoPYara/) |
| :material-book-open-variant: **API documentation** | GitHub Pages | [botacin-s-lab.github.io/AutoPYaraPyPI](https://botacin-s-lab.github.io/AutoPYaraPyPI/) |
| :fontawesome-brands-github: **PyPI source repository** | GitHub | [Botacin-s-Lab/AutoPYaraPyPI](https://github.com/Botacin-s-Lab/AutoPYaraPyPI) |
| :fontawesome-brands-java: **Java backend engine** | GitHub | [Botacin-s-Lab/AutoPYaraBackend](https://github.com/Botacin-s-Lab/AutoPYaraBackend) |
| :material-database: **YARA rules & benchmark data** | Zenodo | [zenodo.org/records/22665898](https://zenodo.org/records/22665898) |
| :fontawesome-brands-python: **Python package** (`pip install autopyara`) | PyPI | [pypi.org/project/autopyara](https://pypi.org/project/autopyara/) |
