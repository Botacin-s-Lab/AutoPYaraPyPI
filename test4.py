import unittest
import os
import shutil
import csv
import time
import yara
from autopyara import AutoPYara

# ==========================================
# CONFIGURATION
# ==========================================
MALWARE_DIR = "/mnt/data/stanic_copy/malware/MLSec21"
BLOOM_MAL = "/home/mtech-server/RetrainedBloomFilters/malicious/"
BLOOM_BEN = "/home/mtech-server/RetrainedBloomFilters/benign/"

# Reduced file count for safety (increase only if this passes)
TEST_FILE_COUNT = 5

class TestAutoPYaraSerial(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[+] Setting up Serial Test Environment...")
        
        # 1. Initialize Tool ONCE (Re-used for all tests)
        try:
            cls.tool = AutoPYara(ngram_top_k=500) 
            print("    - AutoPYara initialized (JVM Started).")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize: {e}")

        # 2. Prepare Files
        if not os.path.exists(MALWARE_DIR):
            raise FileNotFoundError(f"Malware directory not found: {MALWARE_DIR}")
        
        all_files = [os.path.join(MALWARE_DIR, f) for f in os.listdir(MALWARE_DIR) 
                     if os.path.isfile(os.path.join(MALWARE_DIR, f))]
        
        cls.input_files = all_files[:TEST_FILE_COUNT]
        print(f"    - Loaded {len(cls.input_files)} files.")

        # 3. Setup Results
        cls.root_results = os.path.join(os.getcwd(), "test_results_serial")
        if os.path.exists(cls.root_results):
            shutil.rmtree(cls.root_results)
        os.makedirs(cls.root_results)
        
        cls.csv_path = os.path.join(cls.root_results, "summary.csv")
        with open(cls.csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Index", "Status", "Bicluster", "Cluster", "Format", "K", "Time(s)", "Error"])

    def test_all_combinations_serial(self):
        """
        Runs all combinations sequentially in a single loop.
        """
        bicluster_options = ['SpectralCoCluster', 'SpectralCoClusterScale']
        cluster_options = [
            'VBGMM', 'KMeans', 
            'AugmentedKMeansDBSCAN', 'AugmentedKMeansVT'
        ]
        output_formats = ['string', 'yara-python', 'yaramod']
        requires_manual_k = ['KMeans', 'Random']

        # Generate the list of tasks
        tasks = []
        for bi in bicluster_options:
            for cl in cluster_options:
                for fmt in output_formats:
                    tasks.append((bi, cl, fmt))

        total_tasks = len(tasks)
        print(f"\n--- Starting Serial Test ({total_tasks} Combinations) ---")

        for index, (bi, cl, fmt) in enumerate(tasks, 1):
            
            # Print Progress so you know it's alive
            print(f"[{index}/{total_tasks}] Testing: {bi} + {cl} ({fmt})... ", end="", flush=True)
            
            k_input = 3 if cl in requires_manual_k else 0
            start_time = time.time()
            status = "SUCCESS"
            error_msg = ""
            k_val = "N/A"

            try:
                # RUN GENERATION
                # Added rule_name="testrules" here
                result = self.tool.generate(
                    input_files=self.input_files,
                    bloom_malicious=BLOOM_MAL,
                    bloom_benign=BLOOM_BEN,
                    bicluster_alg=bi,
                    cluster_alg=cl,
                    k_cluster=k_input,
                    output_format=fmt,
                    rule_name="testrules",
                    verbose=False
                )
                
                # Validation
                k_val = result.get('k_clusters') or result.get('k') or "Unknown"
                rule_content = result.get('rule_string')
                if not rule_content and isinstance(result.get('output'), str):
                    rule_content = result['output']

                # Save Rule
                if rule_content:
                    save_dir = os.path.join(self.root_results, bi, cl)
                    os.makedirs(save_dir, exist_ok=True)
                    with open(os.path.join(save_dir, f"{fmt}.yar"), 'w') as f:
                        f.write(rule_content)

                print(f"DONE (K={k_val})")

            except Exception as e:
                status = "ERROR"
                error_msg = str(e)
                print(f"FAILED!")
                # We don't stop the loop, we just log the error
            
            duration = time.time() - start_time

            # Log to CSV
            with open(self.csv_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([index, status, bi, cl, fmt, k_val, f"{duration:.2f}", error_msg])

    def test_training_sanity(self):
        print("\n[+] Testing Bloom Filter Training...")
        train_dir = os.path.join(self.root_results, "_TRAINING")
        os.makedirs(train_dir, exist_ok=True)
        for f in self.input_files[:3]:
            shutil.copy(f, train_dir)
            
        try:
            self.tool.train(train_dir, os.path.join(train_dir, "out"), ngram_size=8)
            print("    - Training SUCCESS")
        except Exception as e:
            print(f"    - Training FAILED: {e}")

if __name__ == '__main__':
    unittest.main()