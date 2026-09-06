================================================================================
artifact/ - where the code actually lives
================================================================================

The ACSAC call asks for an `artifact/` directory holding "main code, models, or
data". This directory does NOT contain a copy of AutoPYara's source, and that is
deliberate.

WHY THERE IS NO COPY OF THE SOURCE HERE
--------------------------------------------------------------------------------

This artifact package lives *inside* the tool's own repository, at
ACSACArtifact/. Cloning the repository therefore already gives you the complete
Python frontend. Vendoring a second copy in here would create two versions that
could silently drift apart, which is worse than having one.

WHERE THE CODE IS
--------------------------------------------------------------------------------

    Python frontend (the parent of this directory)
        ../../autopyara/               package source
            core.py                    generate() and train(); the main API
            interface.py               JVM lifecycle and Java<->Python conversion
            augmented_predictor/       ssdeep + DBSCAN pre-clustering
            download.py                Bloom filter data fetching
            jars/AutoYara.jar          the compiled Java backend (binary)
        ../../tests/                   the package's own unit tests
        ../../setup.py                 packaging metadata

        Repository: https://github.com/Botacin-s-Lab/AutoPYaraPyPI
        Released on PyPI: https://pypi.org/project/autopyara/

    Java backend (separate repository; source for the jar above)
        Repository: https://github.com/Botacin-s-Lab/AutoPYaraBackend
        Releases:   https://github.com/Botacin-s-Lab/AutoPYaraBackend/releases

        The jar embedded in the Python package is built from that repository by
        its CI. Each backend release records the commit it was built from, so
        any shipped jar is traceable to its source. To rebuild it:

            git clone https://github.com/Botacin-s-Lab/AutoPYaraBackend.git
            cd AutoPYaraBackend && mvn -B package
            # -> target/AutoYara-<version>.jar

        Architecture and the Java<->Python bridge are documented at
        https://botacin-s-lab.github.io/AutoPYaraPyPI/architecture/

WHAT IS IN THIS DIRECTORY
--------------------------------------------------------------------------------

    make_proxy_corpus.py
        Generates the synthetic sample corpus the claims run against. Produces
        pseudo-random binary files in families sharing planted byte patterns.
        Deterministic (fixed seed), and contains no malicious code. This exists
        because the paper's real corpus cannot be redistributed -- see
        ../use.txt.

        Standalone usage:
            python3 make_proxy_corpus.py --out /tmp/corpus
            python3 make_proxy_corpus.py --out /tmp/corpus --families 3 --per-family 4

    requirements-lock.txt
        Pinned dependency versions matching the environment the claims were
        verified in. See the notes in that file for when to use it.

DATA
--------------------------------------------------------------------------------

The Bloom filter data (~600 MB) is not stored here either. install.sh fetches it
from the data-branch of the frontend repository:

    https://github.com/Botacin-s-Lab/AutoPYaraPyPI/tree/data-branch

It is excluded from the package distribution to keep installs light, and is
downloaded automatically on first use.
