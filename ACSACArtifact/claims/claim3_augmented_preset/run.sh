#!/usr/bin/env bash
#
# Claim 3: the augmented AutoPYara preset runs and determines its own k.
# See claim.txt. Prerequisites: ../../install.sh has been run; Claim 1 passes.
#
# NOTE: this claim is intentionally not bit-reproducible. The CRDEST estimator
# uses an unseeded RNG, so the rule and cluster count may differ between runs.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "================================================================================"
echo "CLAIM 3 - The augmented AutoPYara preset runs and determines its own k"
echo "================================================================================"
echo
echo "Building the synthetic proxy corpus..."
python3 "$ARTIFACT_DIR/artifact/make_proxy_corpus.py" --out "$WORK/corpus"

echo
echo "Running the augmented preset with NO k_cluster supplied"
echo "(ssdeep + DBSCAN -> predictor labels -> CRDEST centroids; a few minutes)..."

WORK="$WORK" python3 - <<'PY'
import os
import sys

work = os.environ["WORK"]
corpus = os.path.join(work, "corpus")
samples = sorted(
    os.path.join(corpus, f) for f in os.listdir(corpus) if f.endswith(".bin")
)

failures = []

def check(label, fn):
    try:
        detail = fn()
        print(f"  [ok]   {label}" + (f" -- {detail}" if detail else ""))
    except Exception as exc:
        print(f"  [FAIL] {label} -- {exc}")
        failures.append(label)

from autopyara import AutoPYara

tool = AutoPYara()

# Deliberately no k_cluster: the augmented path must derive it.
result = tool.generate(
    input_files=samples,
    preset="AutoPYara",
    output_format="string",
    rule_name="acsac_claim3",
)

print()
print("Verifying the result:")

def _returned():
    if result is None:
        raise AssertionError("generate() returned None (no rule met the constraints)")
    return f"{len(result)} keys returned"
check("generate() returned a result", _returned)

def _auto_k():
    k = result.get("k_clusters")
    if k is None:
        raise AssertionError("k_clusters is None -- no cluster count was derived")
    if not isinstance(k, int) or k < 1:
        raise AssertionError(f"k_clusters is not a positive integer: {k!r}")
    return f"auto-derived k_clusters={k} (no k_cluster was supplied)"
check("a cluster count was derived automatically", _auto_k)

def _keys():
    expected = {"rule_string", "k_clusters", "strings", "file_count", "TP", "gram_size"}
    missing = expected - set(result)
    if missing:
        raise AssertionError(f"missing keys: {sorted(missing)}")
    return f"file_count={result['file_count']}, gram_size={result['gram_size']}"
check("result contains the documented keys", _keys)

rule = result.get("rule_string", "") if result else ""

def _nonempty():
    if not rule.strip():
        raise AssertionError("rule_string is empty")
    return f"{len(rule)} chars, {len(rule.splitlines())} lines"
check("rule_string is non-empty", _nonempty)

def _structure():
    for token in ("rule ", "strings:", "condition:"):
        if token not in rule:
            raise AssertionError(f"rule is missing '{token}'")
    n_strings = rule.count("$x")
    if n_strings < 1:
        raise AssertionError("rule declares no hex strings")
    return f"{n_strings} hex string(s) declared"
check("rule is structurally well-formed YARA", _structure)

def _compiles():
    import yara
    yara.compile(source=rule)
    return "accepted by the yara-python compiler"
check("rule compiles as real YARA", _compiles)

def _rejects_k():
    # The augmented path owns k; supplying it must be an error, not silently ignored.
    try:
        tool.generate(
            input_files=samples,
            preset="AutoPYara",
            k_cluster=3,
            output_format="string",
        )
    except ValueError:
        return "ValueError raised, as documented"
    raise AssertionError("supplying k_cluster with preset='AutoPYara' was NOT rejected")
check("k_cluster is rejected with this preset", _rejects_k)

print()
print("-" * 80)
print("Generated rule (first 15 lines):")
print("-" * 80)
for line in rule.splitlines()[:15]:
    print("  " + line)
if len(rule.splitlines()) > 15:
    print(f"  ... ({len(rule.splitlines()) - 15} more lines)")

print()
print("-" * 80)
print("Reminder: this claim is NOT bit-reproducible. The CRDEST estimator uses an")
print("unseeded RNG, so a second run may derive a different k and a different rule.")
print("That is expected -- see claim.txt and ../../use.txt.")
print("-" * 80)

print()
print("=" * 80)
if failures:
    print(f"CLAIM 3: FAIL -- {len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("CLAIM 3: PASS -- the augmented pipeline ran and derived its own cluster count")
print("=" * 80)
PY
