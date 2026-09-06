================================================================================
AutoPYara - ACSAC Artifact Evaluation Package
================================================================================

Artifact for the paper describing AutoPYara, a framework for automated YARA
rule generation from collections of malware samples using Bloom-filtered
byte n-gram analysis and cluster-aware signature construction.

Badges sought:  Artifact Available, Artifact Reviewed
Not sought:     Results Reproduced (see "Scope and limitations" below)

--------------------------------------------------------------------------------
1. WHAT THIS ARTIFACT IS
--------------------------------------------------------------------------------

AutoPYara is distributed as a working, publicly installable tool, not as a
one-off experiment script. It consists of two public repositories:

  Python frontend (this repository)
      https://github.com/Botacin-s-Lab/AutoPYaraPyPI
      Published on PyPI:  https://pypi.org/project/autopyara/

  Java backend (separate repository, compiled into the embedded jar)
      https://github.com/Botacin-s-Lab/AutoPYaraBackend

This directory contains everything needed to install the tool and exercise
it end to end. The tool's own source lives in the parent repository; this
directory does not duplicate it. See artifact/README.txt.

--------------------------------------------------------------------------------
2. QUICK START
--------------------------------------------------------------------------------

From this directory, on a machine meeting the requirements in
infrastructure/resources.txt:

    ./install.sh

That script installs the tool, verifies the Java runtime, and downloads the
pre-trained Bloom filter data. Expect it to take 10-25 minutes, dominated by
a ~600 MB download. It is safe to re-run.

Then run the claims, in order:

    ./claims/claim1_install/run.sh
    ./claims/claim2_autoyara_preset/run.sh
    ./claims/claim3_augmented_preset/run.sh

Each prints a PASS/FAIL summary and exits non-zero on failure. Claim 1 alone
is enough to confirm the installation succeeded, and is the recommended
"kick the tires" check - it takes well under a minute once install.sh has
completed.

A Dockerfile is provided if you prefer a contained environment:

    docker build -t autopyara-artifact -f Dockerfile ..
    docker run --rm -it autopyara-artifact ./claims/claim1_install/run.sh

--------------------------------------------------------------------------------
3. DIRECTORY LAYOUT
--------------------------------------------------------------------------------

    README.txt          This file
    install.sh          One-command setup
    license.txt         License names and URLs
    use.txt             Intended use, limitations, and ethical considerations
    Dockerfile          Contained environment with pinned dependencies

    artifact/           Artifact-specific tooling
        README.txt              Where the tool's source actually lives
        make_proxy_corpus.py    Generates the synthetic sample corpus
        requirements-lock.txt   Pinned dependency versions

    infrastructure/     Execution environment
        resources.txt           Hardware/software requirements, runtimes
        constraints.txt         Why Google Colab is not viable here

    claims/             One directory per demonstrated claim
        claim1_install/         Tool installs and the JVM backend initializes
        claim2_autoyara_preset/ Rule generation via the AutoYara (VBGMM) preset
        claim3_augmented_preset/Rule generation via the augmented preset

--------------------------------------------------------------------------------
4. SCOPE AND LIMITATIONS
--------------------------------------------------------------------------------

This artifact demonstrates that the tool installs and functions correctly. It
deliberately does NOT attempt to regenerate the numerical results in the
paper, for one reason:

    The paper's experiments were run against a malware corpus that cannot be
    redistributed. Shipping live malware in a public artifact is neither
    legally nor ethically appropriate.

Following the ACSAC call's provision for proprietary data ("Proxies for
proprietary data should be included so as to demonstrate the analysis"), this
artifact ships a SYNTHETIC proxy corpus, generated deterministically at run
time by artifact/make_proxy_corpus.py. The proxy contains no malicious code
whatsoever. Each synthetic "family" is built around a large shared contiguous
core wrapped in per-variant unique regions, mirroring the way real malware
variants share reused code and embedded resources. That structure matters: it
is what lets both the n-gram feature path and the fuzzy-hash clustering path
operate on input of a realistic shape. Run

    python3 artifact/make_proxy_corpus.py --out /tmp/c --report

to see the resulting ssdeep similarity matrix (same-family pairs score in the
60s-70s, cross-family pairs score 0).

Consequently the YARA rules produced by the claims below are structurally
valid but not meaningful detection signatures. That is expected. The claims
verify that the pipeline runs and produces well-formed output, not that it
detects real malware families.

Note also that the figures the claims print are NOT a benchmark comparing the
two pipelines against each other. On this corpus both saturate at a 6/6 TP
rate, so it cannot distinguish them; and synthetic data could not support such
a comparison in any case. See the "THESE NUMBERS ARE NOT A BENCHMARK" sections
in the individual claim files.

One further caveat, stated up front: the augmented clustering path uses an
unseeded random number generator, so repeated runs on identical input can
yield different cluster counts and different rules. The claim validators
therefore check structural properties rather than byte-for-byte equality with
a stored output. See use.txt.

--------------------------------------------------------------------------------
5. CONTACT
--------------------------------------------------------------------------------

Maintained by Mabon Ninan, Texas A&M University - ninanmm@tamu.edu

Documentation: https://botacin-s-lab.github.io/AutoPYaraPyPI/
Issue tracker: https://github.com/Botacin-s-Lab/AutoPYaraPyPI/issues
