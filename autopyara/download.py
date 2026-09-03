"""
Downloads the pre-trained Bloom filter data (~500-600MB) that AutoPYara needs
at runtime but does not ship inside the sdist/wheel (see .gitignore:
`autopyara/data/*`). The data lives on the `data-branch` branch of this same
GitHub repository and is pulled down as a branch-archive zip the first time
`autopyara` is imported and the data is missing, or on demand via the
`autopyara-download` console script (see setup.py entry_points).
"""
import os
import zipfile
import urllib.request
import shutil

# --- CONFIGURATION ---
# Source of truth for the bloom filter data: a dedicated branch of this repo.
# Override with environment variables if you host your own mirror/fork.
DATA_REPO = os.environ.get("AUTOPYARA_DATA_REPO", "Botacin-s-Lab/AutoPYaraPyPI")
DATA_BRANCH = os.environ.get("AUTOPYARA_DATA_BRANCH", "data-branch")

URL = f"https://github.com/{DATA_REPO}/archive/refs/heads/{DATA_BRANCH}.zip"
# ---------------------


def download_and_extract():
    install_dir = os.path.dirname(os.path.abspath(__file__))
    dest_zip = os.path.join(install_dir, "data_temp.zip")

    print(f"[+] Downloading bloom filters from {DATA_REPO}@{DATA_BRANCH}...")
    print("    This is ~500-600MB and may take a few minutes.")

    # 1. Download
    try:
        req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(dest_zip, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return

    # 2. Validate that we actually downloaded a ZIP file (Magic Bytes Check)
    with open(dest_zip, 'rb') as f:
        header = f.read(4)
        if header != b'PK\x03\x04':
            print("\n[-] Error: Downloaded file is not a valid ZIP archive.")
            print(f"    Expected a branch archive from {URL}")
            f.seek(0)
            bad_content = f.read(250).decode('utf-8', errors='ignore')
            print(f"    File preview:\n\n{bad_content}...\n")
            os.remove(dest_zip)
            return

    # 3. Extract and Move
    print("[+] Extracting data...")
    try:
        with zipfile.ZipFile(dest_zip, 'r') as z:
            temp_extract_path = os.path.join(install_dir, "_temp_extract")
            z.extractall(temp_extract_path)

            # GitHub branch-archive zips extract into a single wrapper folder
            # named "<repo>-<branch>" (slashes in the branch name become
            # dashes). Search for it, but also handle a flat layout in case
            # the source ever changes to something that isn't wrapped.
            source_data = None

            if os.path.exists(os.path.join(temp_extract_path, "data")):
                source_data = os.path.join(temp_extract_path, "data")
            else:
                for item in os.listdir(temp_extract_path):
                    potential_path = os.path.join(temp_extract_path, item, "data")
                    if os.path.isdir(potential_path):
                        source_data = potential_path
                        break

            if not source_data:
                raise FileNotFoundError("Could not locate the 'data' folder inside the downloaded ZIP.")

            target_data = os.path.join(install_dir, "data")

            # Remove old data if it exists to ensure a clean update
            if os.path.exists(target_data):
                shutil.rmtree(target_data)

            shutil.move(source_data, target_data)

            # Clean up temp folder
            shutil.rmtree(temp_extract_path)

        print(f"[+] Success! Bloom filters installed to: {target_data}")

    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        raise e
    finally:
        if os.path.exists(dest_zip):
            os.remove(dest_zip)


if __name__ == "__main__":
    download_and_extract()
