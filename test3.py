import unittest
import os
import shutil
import tempfile
import csv
import time
import yara
from autopyara import AutoPYara

# ==========================================
# CONFIGURATION
# ==========================================
# Update these paths to match your actual environment
MALWARE_DIR = "/mnt/data/stanic_copy/malware/MLSec21"
BLOOM_MAL = "/home/mtech-server/RetrainedBloomFilters/malicious/"
BLOOM_BEN = "/home/mtech-server/RetrainedBloomFilters/benign/"

# Number of files to test with (Keep small for speed, e.g., 20-50)
TEST_FILE_COUNT = 30

class TestAutoPYaraComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[+] Setting up Comprehensive Test Environment...")
        
        # 1. Initialize Tool
        try:
            cls.tool = AutoPYara(ngram_top_k=500) 
            print("    - AutoPYara initialized.")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize: {e}")

        # 2. Prepare Input Files
        if not os.path.exists(MALWARE_DIR):
            raise FileNotFoundError(f"Malware directory not found: {MALWARE_DIR}")
        
        all_files = [os.path.join(MALWARE_DIR, f) for f in os.listdir(MALWARE_DIR) 
                     if os.path.isfile(os.path.join(MALWARE_DIR, f))]
        
        if len(all_files) == 0:
            raise RuntimeError("No files found in malware directory.")

        cls.input_files = all_files[:TEST_FILE_COUNT]
        print(f"    - Loaded {len(cls.input_files)} files.")

        # 3. Setup Results Directory
        # We create a persistent folder so you can inspect results after the script finishes
        cls.results_dir = os.path.join(os.getcwd(), "test_results_comprehensive")
        if os.path.exists(cls.results_dir):
            shutil.rmtree(cls.results_dir)
        os.makedirs(cls.results_dir)
        print(f"    - Results will be saved to: {cls.results_dir}")

        # 4. Initialize CSV Summary File
        cls.csv_path = os.path.join(cls.results_dir, "summary.csv")
        with open(cls.csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Test_ID", "Bicluster_Alg", "Cluster_Alg", "K_Value", "Status", "Rule_File_Path"])

    def record_result(self, test_id, bi_alg, cl_alg, k_val, status, rule_content=""):
        """Helper to save rule to disk and log to CSV"""
        rule_filename = f"{test_id}_{bi_alg}_{cl_alg}.yar"
        rule_path = os.path.join(self.results_dir, rule_filename)
        
        # Save Rule Text
        if rule_content:
            with open(rule_path, 'w') as f:
                f.write(rule_content)
        else:
            rule_path = "N/A"

        # Log to CSV
        with open(self.csv_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([test_id, bi_alg, cl_alg, k_val, status, rule_path])

    def test_all_algorithm_combinations(self):
        """
        Matrix Test: Runs every combination of Biclustering and Clustering algorithms.
        """
        print("\n--- Starting Matrix Test of All Algorithms ---")

        bicluster_options = ['SpectralCoCluster', 'SpectralCoClusterScale']
        
        cluster_options = [
            # Standard / Legacy
            'VBGMM', 
            'KMeans', 
            'KMeansSoft', 
            'Random',
            # Augmented (Your New Features)
            'AugmentedKMeansDBSCAN', 
            'AugmentedKMeansDBSCANSoft', 
            'AugmentedKMeansVT', 
            'AugmentedKMeansVTSoft'
        ]

        # Algorithms that require a fixed K (VBGMM and Augmented calculate it themselves)
        requires_manual_k = ['KMeans', 'KMeansSoft', 'Random']

        test_counter = 1

        for bi_alg in bicluster_options:
            for cl_alg in cluster_options:
                
                # Use subTest so one failure doesn't stop the whole loop
                with self.subTest(bicluster=bi_alg, cluster=cl_alg):
                    print(f"\n[{test_counter}] Testing: {bi_alg} + {cl_alg}")
                    
                    # Logic to provide K only if the algorithm is "dumb" (Standard KMeans)
                    # VBGMM and Augmented calculate K automatically.
                    k_input = 0
                    if cl_alg in requires_manual_k:
                        k_input = 3 # Force K=3 for algorithms that can't infer it
                        print(f"    -> Manual K={k_input} provided for non-inferring algorithm.")

                    try:
                        # --- GENERATE ---
                        start_time = time.time()
                        result = self.tool.generate(
                            input_files=self.input_files,
                            bloom_malicious=BLOOM_MAL,
                            bloom_benign=BLOOM_BEN,
                            bicluster_alg=bi_alg,
                            cluster_alg=cl_alg,
                            k_cluster=k_input, # Will be 0 (auto) or 3 (manual)
                            output_format="string",
                            verbose=False # Keep console clean, check CSV for details
                        )
                        duration = time.time() - start_time

                        # --- VERIFY ---
                        # 1. Check K exists
                        k_final = result.get('k_clusters') or result.get('k')
                        self.assertIsNotNone(k_final, "K value was None")
                        
                        # 2. Check Rule String exists
                        rule_str = result.get('output', '')
                        self.assertTrue(len(rule_str) > 0, "Generated rule string was empty")

                        # 3. Log Success
                        print(f"    -> SUCCESS: K={k_final} (Time: {duration:.2f}s)")
                        self.record_result(test_counter, bi_alg, cl_alg, k_final, "SUCCESS", rule_str)

                    except Exception as e:
                        # Log Failure
                        print(f"    -> FAILED: {str(e)}")
                        self.record_result(test_counter, bi_alg, cl_alg, "ERR", f"ERROR: {str(e)}")
                        # Fail the subtest so unittest reports it
                        self.fail(f"Algorithm combination {bi_alg}/{cl_alg} failed: {e}")
                    
                    test_counter += 1

    def test_training_workflow(self):
        """Test the training capability explicitly and save logs"""
        print("\n--- Testing Bloom Filter Training ---")
        train_in = os.path.join(self.results_dir, "training_input_samples")
        train_out = os.path.join(self.results_dir, "trained_blooms")
        os.makedirs(train_in, exist_ok=True)
        os.makedirs(train_out, exist_ok=True)

        # Copy 3 samples
        for f in self.input_files[:3]:
            shutil.copy(f, train_in)

        try:
            self.tool.train(train_in, train_out, ngram_size=8)
            
            files = os.listdir(train_out)
            bloom_count = len([f for f in files if f.endswith(".bloom")])
            
            if bloom_count > 0:
                print(f"    -> SUCCESS: Created {bloom_count} bloom filters.")
                self.record_result("TRAIN", "N/A", "BloomFilter", bloom_count, "SUCCESS", f"Generated in {train_out}")
            else:
                self.record_result("TRAIN", "N/A", "BloomFilter", 0, "FAILED", "No files created")
                self.fail("No .bloom files generated")

        except Exception as e:
            self.record_result("TRAIN", "N/A", "BloomFilter", 0, "ERROR", str(e))
            self.fail(f"Training failed: {e}")

if __name__ == '__main__':
    unittest.main()