#!/usr/bin/env bash
#
# Claim 1: AutoPYara installs and its JVM backend initializes correctly.
# See claim.txt. Prerequisite: ../../install.sh has been run.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "================================================================================"
echo "CLAIM 1 - AutoPYara installs and its JVM backend initializes"
echo "================================================================================"

ARTIFACT_DIR="$ARTIFACT_DIR" WORK="$WORK" python3 - <<'PY'
import os
import subprocess
import sys

artifact_dir = os.environ["ARTIFACT_DIR"]
work = os.environ["WORK"]

failures = []

def check(label, fn):
    try:
        detail = fn()
        print(f"  [ok]   {label}" + (f" -- {detail}" if detail else ""))
    except Exception as exc:
        print(f"  [FAIL] {label} -- {exc}")
        failures.append(label)

print("\n1. Package import")

def _import():
    import autopyara
    import importlib.metadata as md
    return f"autopyara {md.version('autopyara')}"
check("autopyara imports and reports a version", _import)

print("\n2. Java backend")

def _jvm():
    from autopyara import AutoPYara
    tool = AutoPYara()                      # starts the JVM, loads AutoYara.jar
    globals()["_tool"] = tool
    import jpype
    return f"JVM started (JPype {jpype.__version__})"
check("AutoPYara() constructs and the JVM starts", _jvm)

def _jar():
    import autopyara, os
    jar = os.path.join(os.path.dirname(autopyara.__file__), "jars", "AutoYara.jar")
    if not os.path.isfile(jar):
        raise AssertionError(f"jar not found at {jar}")
    return f"{os.path.getsize(jar) / 1e6:.1f} MB"
check("AutoYara.jar is present", _jar)

print("\n3. Bloom filter data")

def _blooms():
    import autopyara, os
    root = os.path.join(os.path.dirname(autopyara.__file__), "data", "blooms")
    missing, found = [], 0
    for flavour in ("ember", "autopyara"):
        for kind in ("benign", "malicious"):
            d = os.path.join(root, flavour, kind)
            if not os.path.isdir(d):
                missing.append(f"{flavour}/{kind}")
            else:
                found += len([f for f in os.listdir(d) if f.endswith(".bloom")])
    if missing:
        raise AssertionError("missing sets: " + ", ".join(missing))
    return f"4/4 sets present, {found} .bloom files"
check("all four Bloom filter sets are present", _blooms)

print("\n4. Synthetic proxy corpus")

def _corpus():
    gen = os.path.join(artifact_dir, "artifact", "make_proxy_corpus.py")
    out = os.path.join(work, "corpus")
    subprocess.run([sys.executable, gen, "--out", out], check=True,
                   stdout=subprocess.DEVNULL)
    samples = sorted(f for f in os.listdir(out) if f.endswith(".bin"))
    if len(samples) != 6:
        raise AssertionError(f"expected 6 samples, got {len(samples)}")
    if not os.path.isfile(os.path.join(out, "MANIFEST.txt")):
        raise AssertionError("MANIFEST.txt not written")
    return f"{len(samples)} samples across 2 families"
check("proxy corpus generator produces a valid corpus", _corpus)

print()
print("=" * 80)
if failures:
    print(f"CLAIM 1: FAIL -- {len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("CLAIM 1: PASS -- installation is sound and the backend is operational")
print("=" * 80)
PY
