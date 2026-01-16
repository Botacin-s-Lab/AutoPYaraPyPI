import unittest
import os
import shutil
import csv
import time
import autopyara
from autopyara import AutoPYara

# ==========================================
# CONFIGURATION
# ==========================================
MALWARE_DIR = "/mnt/data/stanic_copy/malware/MLSec21"
TEST_FILE_COUNT = 5

# 1. "autopyara" = Package uses default filters automatically
# 2. "ember"     = Package finds Ember filters automatically
# 3. "/path/..." = Test script expands this to /malicious and /benign
EXPERIMENT_FLAGS = [
    "autopyara", 
    "ember", 
    "/home/mtech-server/RetrainedBloomFilters" 
]

class TestAutoPYaraSmartConfigs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[+] Setting up New Package Test Environment...")
        
        # 1. Initialize Tool
        try:
            cls.tool = AutoPYara(ngram_top_k=500) 
            print("    - AutoPYara initialized.")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize: {e}")

        # 2. Load Files
        if not os.path.exists(MALWARE_DIR):
            raise FileNotFoundError(f"Malware directory not found: {MALWARE_DIR}")
        
        all_files = [os.path.join(MALWARE_DIR, f) for f in os.listdir(MALWARE_DIR) 
                     if os.path.isfile(os.path.join(MALWARE_DIR, f))]
        
        cls.input_files = all_files[:TEST_FILE_COUNT]
        print(f"    - Loaded {len(cls.input_files)} files.")

        # 3. Setup Results
        cls.root_results = os.path.join(os.getcwd(), "test_results_smart")
        if os.path.exists(cls.root_results):
            shutil.rmtree(cls.root_results)
        os.makedirs(cls.root_results)
        
        cls.csv_path = os.path.join(cls.root_results, "summary.csv")
        with open(cls.csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Index", "Config_Flag", "Status", "Bicluster", "Cluster", "Format", "K", "Time(s)", "Error"])

    def test_smart_configurations(self):
        
        bicluster_options = ['SpectralCoCluster', 'SpectralCoClusterScale']
        cluster_options = ['VBGMM', 'KMeans', 'AugmentedKMeansDBSCAN', 'AugmentedKMeansVT']
        output_formats = ['string', 'yara-python', 'yaramod']
        requires_manual_k = ['KMeans', 'Random']

        tasks = []
        for flag in EXPERIMENT_FLAGS:
            for bi in bicluster_options:
                for cl in cluster_options:
                    for fmt in output_formats:
                        tasks.append((flag, bi, cl, fmt))

        total_tasks = len(tasks)
        print(f"\n--- Starting Test ({total_tasks} Tasks) ---")

        for index, (flag, bi, cl, fmt) in enumerate(tasks, 1):
            
            # --- ARGUMENT PREPARATION ---
            # If it's a known internal flag, we pass it raw.
            # If it's a custom path, we construct the subpaths here.
            
            if flag in ["autopyara", "ember"]:
                # The package handles "ember" -> "autopyara/data/blooms/ember/..." internally
                b_mal = flag
                b_ben = flag # The package will overwrite this anyway based on the flag
                config_name = flag
            else:
                # Custom User Path: We assume standard /malicious and /benign structure
                b_mal = os.path.join(flag, "malicious")
                b_ben = os.path.join(flag, "benign")
                config_name = "Custom_User_Path"

            print(f"[{index}/{total_tasks}] [{config_name}] {bi} + {cl}... ", end="", flush=True)
            
            k_input = 3 if cl in requires_manual_k else 0
            start_time = time.time()
            status = "SUCCESS"
            error_msg = ""
            k_val = "N/A"

            try:
                # --- CALLING THE NEW PACKAGE ---
                result = self.tool.generate(
                    input_files=self.input_files,
                    bloom_malicious=b_mal, # Passed as flag ("ember") or path
                    bloom_benign=b_ben,    # Passed as flag ("ember") or path
                    bicluster_alg=bi,
                    cluster_alg=cl,
                    k_cluster=k_input,
                    output_format=fmt,
                    rule_name="testrules",
                    verbose=False
                )
                
                # Validation
                k_val = result.get('k_clusters') or result.get('k') or "Unknown"
                rule_content = result.get('rule_string') or result.get('output')

                # Save Rule
                if rule_content and isinstance(rule_content, str):
                    save_dir = os.path.join(self.root_results, config_name, bi, cl)
                    os.makedirs(save_dir, exist_ok=True)
                    with open(os.path.join(save_dir, f"{fmt}.yar"), 'w') as f:
                        f.write(rule_content)

                print(f"DONE (K={k_val})")

            except Exception as e:
                status = "ERROR"
                error_msg = str(e)
                print(f"FAILED!")

            duration = time.time() - start_time

            with open(self.csv_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([index, config_name, status, bi, cl, fmt, k_val, f"{duration:.2f}", error_msg])

if __name__ == '__main__':
    unittest.main()