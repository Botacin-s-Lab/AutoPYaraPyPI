"""
End-to-end functional smoke tests: real JVM, real yara-python/yaramod, real
built-in bloom filters, run against small synthetic dummy files generated at
test time (never real malware, so this is safe to run in public CI and needs
no private data).

Adapted from the ad hoc test.py/test2.py scripts on the TestPyPI branch,
which hardcoded a private malware corpus and a local retrained-bloom-filter
path and so could not run outside the original dev machine.

Requires: a JRE on PATH/JAVA_HOME, and the bloom filter data already present
(either pre-downloaded, or this will trigger the real ~500-600MB auto-download
on first import).
"""
import os
import random

import pytest
import yara

from autopyara import AutoPYara

BUILTIN_BLOOM_FLAGS = ["ember", "autopyara"]


@pytest.fixture(scope="module")
def sample_files(tmp_path_factory):
    """A handful of small synthetic (non-malicious) dummy files, not real
    malware, just enough for the pipeline to have something to chew on."""
    d = tmp_path_factory.mktemp("dummy_samples")
    rng = random.Random(1234)
    paths = []
    for i in range(3):
        p = d / f"sample_{i}.bin"
        p.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)))
        paths.append(str(p))
    return paths


@pytest.fixture(scope="module")
def tool():
    return AutoPYara()


@pytest.mark.parametrize("bloom_flag", BUILTIN_BLOOM_FLAGS)
def test_autoyara_preset_string_output(tool, sample_files, bloom_flag):
    result = tool.generate(
        input_files=sample_files,
        bloom_malicious=bloom_flag,
        bloom_benign=bloom_flag,
        preset="AutoYara",
        k_cluster=1,
        output_format="string",
        rule_name="ci_smoke_test",
    )
    assert result["rule_string"]
    assert "ci_smoke_test" in result["rule_string"]
    assert result["output"] == result["rule_string"]


@pytest.mark.parametrize("bloom_flag", BUILTIN_BLOOM_FLAGS)
def test_autopyara_preset_auto_k(tool, sample_files, bloom_flag):
    result = tool.generate(
        input_files=sample_files,
        bloom_malicious=bloom_flag,
        bloom_benign=bloom_flag,
        preset="AutoPYara",
        output_format="string",
        rule_name="ci_smoke_test",
    )
    assert result["rule_string"]
    assert result["k_clusters"] is not None


def test_yara_python_output_format_compiles(tool, sample_files):
    result = tool.generate(
        input_files=sample_files,
        bloom_malicious="ember",
        bloom_benign="ember",
        preset="AutoYara",
        k_cluster=1,
        output_format="yara-python",
        rule_name="ci_smoke_test",
    )
    assert isinstance(result["output"], yara.Rules)
