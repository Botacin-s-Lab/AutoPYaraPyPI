"""
Unit tests for the pure-Python helpers in autopyara.core. These do not
require a JVM/Java, network access, or the bloom filter data (see
AUTOPYARA_SKIP_AUTO_DOWNLOAD in conftest.py), only the runtime dependencies
declared in setup.py's install_requires.
"""
import os

from autopyara.core import resolve_bloom_path, sanitize_rule_name

BLOOMS_PATH = os.path.join("some", "package", "data", "blooms")


def test_resolve_bloom_path_ember_flag():
    assert resolve_bloom_path(BLOOMS_PATH, "ember", "malicious") == os.path.join(
        BLOOMS_PATH, "ember", "malicious"
    )


def test_resolve_bloom_path_ember_flag_is_case_insensitive():
    assert resolve_bloom_path(BLOOMS_PATH, "EMBER", "benign") == os.path.join(
        BLOOMS_PATH, "ember", "benign"
    )


def test_resolve_bloom_path_autopyara_flag():
    assert resolve_bloom_path(BLOOMS_PATH, "autopyara", "malicious") == os.path.join(
        BLOOMS_PATH, "autopyara", "malicious"
    )


def test_resolve_bloom_path_passes_through_custom_path():
    custom = "/absolute/path/to/custom/malicious_bloom"
    assert resolve_bloom_path(BLOOMS_PATH, custom, "malicious") == custom


def test_sanitize_rule_name_default_when_empty():
    assert sanitize_rule_name(None) == "autoyara_rule"
    assert sanitize_rule_name("") == "autoyara_rule"


def test_sanitize_rule_name_strips_invalid_characters():
    assert sanitize_rule_name("my rule!-name") == "my_rule__name"


def test_sanitize_rule_name_prefixes_leading_digit():
    assert sanitize_rule_name("123_rule") == "rule_123_rule"


def test_sanitize_rule_name_leaves_valid_name_untouched():
    assert sanitize_rule_name("my_custom_rule") == "my_custom_rule"
