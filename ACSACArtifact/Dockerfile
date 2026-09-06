# Contained environment for the AutoPYara ACSAC artifact.
#
# Provides a pinned Python + JRE + dependency set, so evaluation does not depend
# on what happens to be installed on the host, or on what PyPI resolves to on
# the day it is run.
#
# BUILD  (note the context is the REPOSITORY ROOT, not this directory, because
#         the image installs the package from source)
#
#     docker build -t autopyara-artifact -f ACSACArtifact/Dockerfile .
#
# RUN
#
#     # quick check (~1 min once built)
#     docker run --rm -it autopyara-artifact ./claims/claim1_install/run.sh
#
#     # the functional claims
#     docker run --rm -it autopyara-artifact ./claims/claim2_autoyara_preset/run.sh
#     docker run --rm -it autopyara-artifact ./claims/claim3_augmented_preset/run.sh
#
#     # interactive shell
#     docker run --rm -it autopyara-artifact bash
#
# MEMORY -- IMPORTANT
#     The JVM backend is started with a fixed 14 GB maximum heap, which is not
#     configurable in this release. Give the container enough memory or the
#     kernel will terminate it partway through a run:
#
#         docker run --rm -it --memory=16g autopyara-artifact ...
#
#     See infrastructure/constraints.txt for the full explanation.
#
# NOTE ON IMAGE SIZE
#     The image does NOT bake in the ~600 MB Bloom filter data; it is fetched on
#     first use and lives only in the running container. To avoid re-downloading
#     it on every `docker run`, mount a volume over the data directory, or run
#     the claims from a single long-lived container started with `bash`.

FROM eclipse-temurin:17-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Python 3.10 is the jammy default and sits inside the supported 3.9-3.12 range.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/autopyara

# Dependencies first, pinned, so this layer caches independently of source edits.
COPY ACSACArtifact/artifact/requirements-lock.txt /tmp/requirements-lock.txt
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install -r /tmp/requirements-lock.txt

# Then the package itself, installed without dependency resolution so the pins
# above are what actually get used.
COPY . /opt/autopyara
RUN python3 -m pip install --no-deps /opt/autopyara

# Fail fast at build time if the JVM cannot start, rather than at evaluation time.
RUN python3 -c "from autopyara import AutoPYara; AutoPYara(); print('JVM OK')"

WORKDIR /opt/autopyara/ACSACArtifact
RUN chmod +x install.sh claims/*/run.sh artifact/make_proxy_corpus.py

CMD ["bash", "-lc", "echo 'AutoPYara artifact container. Run e.g. ./claims/claim1_install/run.sh'; exec bash"]
