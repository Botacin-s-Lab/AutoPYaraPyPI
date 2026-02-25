# import os
# import zipfile
# import urllib.request
# import shutil

# # --- CONFIGURATION ---
# GITHUB_USER = "Botacin-s-Lab"
# REPO_NAME = "AutoPYaraPyPI"
# BRANCH_NAME = "data-branch"
# # ---------------------

# URL = f"https://github.com/{GITHUB_USER}/{REPO_NAME}/archive/refs/heads/{BRANCH_NAME}.zip"

# def download_and_extract():
#     # 1. FIX: Find the install directory dynamically without pkg_resources
#     # Since download.py is inside the autopyara folder, we just get its directory!
#     install_dir = os.path.dirname(os.path.abspath(__file__))
#     dest_zip = os.path.join(install_dir, "data_temp.zip")
    
#     print(f"[+] Downloading bloom filters from {GITHUB_USER}/{REPO_NAME}...")
    
#     # 2. Download
#     try:
#         req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
#         with urllib.request.urlopen(req) as response, open(dest_zip, 'wb') as out_file:
#             shutil.copyfileobj(response, out_file)
#     except Exception as e:
#         print(f"[-] Download failed: {e}")
#         return

#     # 3. FIX: Validate that we actually downloaded a ZIP file (Magic Bytes Check)
#     with open(dest_zip, 'rb') as f:
#         header = f.read(4)
#         if header != b'PK\x03\x04':
#             print("\n[-] Error: Downloaded file is not a valid ZIP archive.")
#             print("    Is the GitHub repository set to PRIVATE? If so, GitHub blocked the download and sent an HTML login page instead.")
            
#             # Print a preview of what we actually downloaded to help debug
#             f.seek(0)
#             bad_content = f.read(250).decode('utf-8', errors='ignore')
#             print(f"    File preview:\n\n{bad_content}...\n")
            
#             os.remove(dest_zip)
#             return

#     # 4. Extract and Move
#     print("[+] Extracting data...")
#     try:
#         with zipfile.ZipFile(dest_zip, 'r') as z:
#             temp_extract_path = os.path.join(install_dir, "_temp_extract")
#             z.extractall(temp_extract_path)
            
#             # GitHub zips wrap everything in a folder like "AutoPYaraPyPI-data-branch"
#             extracted_items = os.listdir(temp_extract_path)
#             inner_folder_name = extracted_items[0]
#             inner_folder_path = os.path.join(temp_extract_path, inner_folder_name)
            
#             # We want to move the 'data' folder from inside there to 'autopyara/data'
#             source_data = os.path.join(inner_folder_path, "data")
#             target_data = os.path.join(install_dir, "data")

#             # Remove old data if it exists to ensure a clean update
#             if os.path.exists(target_data):
#                 shutil.rmtree(target_data)
                
#             shutil.move(source_data, target_data)
            
#             # Clean up temp folder
#             shutil.rmtree(temp_extract_path)

#         print(f"[+] Success! Bloom filters installed to: {target_data}")
        
#     except Exception as e:
#         print(f"[-] Extraction failed: {e}")
#     finally:
#         if os.path.exists(dest_zip):
#             os.remove(dest_zip)

# if __name__ == "__main__":
#     download_and_extract()

import os
import zipfile
import urllib.request
import shutil

# --- CONFIGURATION (Anonymized for Peer Review) ---
ANON_REPO_ID = "AutoPYaraPyPI-8163" 

# The 4open.science API endpoint for downloading the repo as a ZIP
URL = f"https://anonymous.4open.science/api/repo/{ANON_REPO_ID}/zip"
# --------------------------------------------------

def download_and_extract():
    install_dir = os.path.dirname(os.path.abspath(__file__))
    dest_zip = os.path.join(install_dir, "data_temp.zip")
    
    print(f"[+] Downloading bloom filters anonymously (ID: {ANON_REPO_ID})...")
    print(f"    This may take a minute or two depending on the proxy server.")
    
    # 2. Download
    try:
        req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(dest_zip, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return

    # 3. Validate that we actually downloaded a ZIP file (Magic Bytes Check)
    with open(dest_zip, 'rb') as f:
        header = f.read(4)
        if header != b'PK\x03\x04':
            print("\n[-] Error: Downloaded file is not a valid ZIP archive.")
            print("    The anonymous proxy server might be blocking automated downloads or the file is too large.")
            
            # Print a preview of what we actually downloaded to help debug
            f.seek(0)
            bad_content = f.read(250).decode('utf-8', errors='ignore')
            print(f"    File preview:\n\n{bad_content}...\n")
            
            os.remove(dest_zip)
            return

    # 4. Extract and Move
    print("[+] Extracting data...")
    try:
        with zipfile.ZipFile(dest_zip, 'r') as z:
            temp_extract_path = os.path.join(install_dir, "_temp_extract")
            z.extractall(temp_extract_path)
            
            # Smarter search: Look for the 'data' folder dynamically
            source_data = None
            
            # Check if it extracted flat (Anonymous GitHub style)
            if os.path.exists(os.path.join(temp_extract_path, "data")):
                source_data = os.path.join(temp_extract_path, "data")
            else:
                # Check if it has a wrapper folder (Standard GitHub style)
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
        raise e  # <-- Added this so it doesn't falsely report "Setup complete!"
    finally:
        if os.path.exists(dest_zip):
            os.remove(dest_zip)

if __name__ == "__main__":
    download_and_extract()