import os
import zipfile
import urllib.request
import shutil
import pkg_resources

# --- CONFIGURATION ---
GITHUB_USER = "Botacin-s-Lab"
REPO_NAME = "AutoPYaraPyPI"
BRANCH_NAME = "data-branch"
# ---------------------

# This URL automatically zips the current state of that branch
URL = f"https://github.com/{GITHUB_USER}/{REPO_NAME}/archive/refs/heads/{BRANCH_NAME}.zip"

def download_and_extract():
    try:
        # Find where autopyara is installed on the user's machine
        install_dir = pkg_resources.resource_filename("autopyara", "")
    except ImportError:
        print("[-] Error: autopyara package not found. Is it installed?")
        return

    dest_zip = os.path.join(install_dir, "data_temp.zip")
    
    print(f"[+] Downloading bloom filters from {GITHUB_USER}/{REPO_NAME}...")
    
    # 1. Download
    try:
        opener = urllib.request.build_opener()
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib.request.install_opener(opener)
        urllib.request.urlretrieve(URL, dest_zip)
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return

    # 2. Extract and Move
    print("[+] Extracting data...")
    try:
        with zipfile.ZipFile(dest_zip, 'r') as z:
            temp_extract_path = os.path.join(install_dir, "_temp_extract")
            z.extractall(temp_extract_path)
            
            # GitHub zips wrap everything in a folder like "AutoPYaraPyPI-data-branch"
            inner_folder_name = os.listdir(temp_extract_path)[0]
            inner_folder_path = os.path.join(temp_extract_path, inner_folder_name)
            
            # We want to move the 'data' folder from inside there to 'autopyara/data'
            source_data = os.path.join(inner_folder_path, "data")
            target_data = os.path.join(install_dir, "data")

            # Remove old data if it exists to ensure a clean update
            if os.path.exists(target_data):
                shutil.rmtree(target_data)
                
            shutil.move(source_data, target_data)
            
            # Clean up temp folder
            shutil.rmtree(temp_extract_path)

        print("[+] Success! Bloom filters are installed.")
        
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
    finally:
        if os.path.exists(dest_zip):
            os.remove(dest_zip)

if __name__ == "__main__":
    download_and_extract()