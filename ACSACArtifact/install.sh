#!/usr/bin/env bash
#
# One-command setup for the AutoPYara ACSAC artifact.
#
# Installs the tool, verifies its Java dependency, and fetches the pre-trained
# Bloom filter data. Safe to re-run: each step is skipped if already satisfied.
#
# Usage:   ./install.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

step()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()    { printf '    [ok] %s\n' "$*"; }
fail()  { printf '    [FAIL] %s\n' "$*" >&2; exit 1; }
note()  { printf '    %s\n' "$*"; }

# ------------------------------------------------------------------------------
step "1/5  Checking Python"
# ------------------------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH."

PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 - <<'PY' || fail "Python 3.9 or newer is required (found $PY_VER)."
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 9) else 1)
PY
ok "python3 $PY_VER"

# ------------------------------------------------------------------------------
step "2/5  Checking Java"
# ------------------------------------------------------------------------------
# AutoPYara's rule-generation backend runs inside a JVM. Without a JRE the
# package installs fine but fails the moment AutoPYara() is constructed, so we
# check here rather than letting a reviewer hit it later.
if ! command -v java >/dev/null 2>&1 && [ -z "${JAVA_HOME:-}" ]; then
    fail "No Java runtime found.
       AutoPYara requires a JRE 11 or newer on PATH, or JAVA_HOME set.
       On Debian/Ubuntu:  sudo apt-get install -y default-jre"
fi
JAVA_VER="$(java -version 2>&1 | head -1 || echo 'unknown')"
ok "$JAVA_VER"

# ------------------------------------------------------------------------------
step "3/5  Installing AutoPYara"
# ------------------------------------------------------------------------------
# Installed from this repository (not PyPI) so that reviewers evaluate exactly
# the source they were given.
note "Installing from $REPO_ROOT"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet "$REPO_ROOT"
INSTALLED="$(python3 -c 'import importlib.metadata as m; print(m.version("autopyara"))')"
ok "autopyara $INSTALLED installed"

# ------------------------------------------------------------------------------
step "4/5  Fetching the Bloom filter data (~600 MB)"
# ------------------------------------------------------------------------------
# Not bundled in the distribution to keep installs light; pulled from the
# data-branch of the project repository. This is the slow step.
DATA_DIR="$(python3 -c 'import autopyara, os; print(os.path.join(os.path.dirname(autopyara.__file__), "data", "blooms"))' 2>/dev/null || true)"

if [ -n "$DATA_DIR" ] && [ -d "$DATA_DIR" ]; then
    ok "Bloom filter data already present at $DATA_DIR"
else
    note "Downloading - this typically takes 10-20 minutes."
    autopyara-download
    DATA_DIR="$(python3 -c 'import autopyara, os; print(os.path.join(os.path.dirname(autopyara.__file__), "data", "blooms"))')"
    [ -d "$DATA_DIR" ] || fail "Download completed but $DATA_DIR is missing."
    ok "Bloom filter data installed at $DATA_DIR"
fi

# ------------------------------------------------------------------------------
step "5/5  Verifying the installation"
# ------------------------------------------------------------------------------
python3 - <<'PY' || fail "Verification failed."
import os
from autopyara import AutoPYara

tool = AutoPYara()                       # starts the JVM; fails loudly if Java is unusable
import autopyara
blooms = os.path.join(os.path.dirname(autopyara.__file__), "data", "blooms")
for flavour in ("ember", "autopyara"):
    for kind in ("benign", "malicious"):
        p = os.path.join(blooms, flavour, kind)
        assert os.path.isdir(p), f"missing Bloom filter directory: {p}"
print("    [ok] JVM started and all four Bloom filter sets are present")
PY

cat <<EOF

================================================================================
Setup complete.

Next, run the claims in order:

    ./claims/claim1_install/run.sh
    ./claims/claim2_autoyara_preset/run.sh
    ./claims/claim3_augmented_preset/run.sh

Claim 1 is the recommended quick check and finishes in under a minute.
================================================================================
EOF
