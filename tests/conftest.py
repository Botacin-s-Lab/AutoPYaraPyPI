import os

# Never let the test suite trigger the ~500-600MB bloom filter auto-download
# as a side effect of merely importing `autopyara` (e.g. in test_core_helpers.py,
# which only needs the pure-Python helpers). Tests that actually need the real
# bloom data (test_smoke_generate.py) rely on it already being present -
# CI restores it from cache or downloads it explicitly before running pytest.
os.environ.setdefault("AUTOPYARA_SKIP_AUTO_DOWNLOAD", "1")
