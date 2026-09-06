#!/usr/bin/env bash
#
# Claim 2: the AutoYara (VBGMM) preset generates a valid YARA rule.
# See claim.txt. Prerequisites: ../../install.sh has been run; Claim 1 passes.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "================================================================================"
echo "CLAIM 2 - The AutoYara (VBGMM) preset generates a valid YARA rule"
echo "================================================================================"
echo
echo "Building the synthetic proxy corpus..."
python3 "$ARTIFACT_DIR/artifact/make_proxy_corpus.py" --out "$WORK/corpus"

echo
echo "Running the AutoYara preset (this takes a minute or two)..."

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
result = tool.generate(
    input_files=samples,
    preset="AutoYara",        # VBGMM clustering
    k_cluster=1,
    output_format="string",
    rule_name="acsac_claim2",
)

print()
print("Verifying the result:")

def _returned():
    if result is None:
        raise AssertionError("generate() returned None (no rule met the constraints)")
    return f"{len(result)} keys returned"
check("generate() returned a result", _returned)

def _keys():
    expected = {"rule_string", "k_clusters", "strings", "file_count", "TP", "gram_size"}
    missing = expected - set(result)
    if missing:
        raise AssertionError(f"missing keys: {sorted(missing)}")
    return f"k_clusters={result['k_clusters']}, file_count={result['file_count']}, gram_size={result['gram_size']}"
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
    if "{" not in rule or "}" not in rule:
        raise AssertionError("rule has no braces")
    n_strings = rule.count("$x")
    if n_strings < 1:
        raise AssertionError("rule declares no hex strings")
    return f"{n_strings} hex string(s) declared"
check("rule is structurally well-formed YARA", _structure)

def _named():
    if "acsac_claim2" not in rule:
        raise AssertionError("rule_name argument was not honoured")
    return "rule_name honoured"
check("rule carries the requested name", _named)

def _compiles():
    import yara
    compiled = yara.compile(source=rule)
    globals()["_compiled"] = compiled
    return "accepted by the yara-python compiler"
check("rule compiles as real YARA", _compiles)

def _scans():
    compiled = globals().get("_compiled")
    if compiled is None:
        raise AssertionError("no compiled rule to scan with")
    matches = compiled.match(samples[0])
    return f"scanned a sample, {len(matches)} match(es)"
check("compiled rule can scan a file", _scans)

print()
print("-" * 80)
print("Generated rule (first 25 lines):")
print("-" * 80)
for line in rule.splitlines()[:25]:
    print("  " + line)
if len(rule.splitlines()) > 25:
    print(f"  ... ({len(rule.splitlines()) - 25} more lines)")

print()
print("=" * 80)
if failures:
    print(f"CLAIM 2: FAIL -- {len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("CLAIM 2: PASS -- the AutoYara preset produced a valid, compilable YARA rule")
print("=" * 80)
PY
