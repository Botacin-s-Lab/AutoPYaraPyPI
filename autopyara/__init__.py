import os
from .core import AutoPYara
from .download import download_and_extract

# 1. Define where the data should be using standard Python (No pkg_resources!)
_ROOT = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_ROOT, "data", "blooms")

# 2. Check if data exists. If not, auto-download.
if not os.path.exists(_DATA_DIR):
    print("\n[AutoPYara] ---------------------------------------------------------")
    print("[AutoPYara] First-time setup detected: Bloom filters are missing.")
    print("[AutoPYara] Downloading necessary data files from GitHub (approx 200MB)...")
    print("[AutoPYara] This only happens once.")
    print("[AutoPYara] ---------------------------------------------------------\n")
    
    try:
        download_and_extract()
        print("\n[AutoPYara] Setup complete! You can now use the tool.\n")
    except Exception as e:
        print(f"[AutoPYara] WARNING: Auto-download failed: {e}")
        print("[AutoPYara] Please run 'autopyara-download' manually.")

# 3. Expose the main class
__all__ = ["AutoPYara"]