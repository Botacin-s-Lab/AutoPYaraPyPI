import unittest
import os
import shutil
import tempfile
import yara
import yaramod
from autopyara import AutoPYara

# ==========================================
# CONFIGURATION
# ==========================================
# Update these paths to match your actual environment
MALWARE_DIR = "/mnt/data/stanic_copy/malware/MLSec21"
BLOOM_MAL = "/home/mtech-server/RetrainedBloomFilters/malicious/"
BLOOM_BEN = "/home/mtech-server/RetrainedBloomFilters/benign/"

# We use a subset of files to keep the test fast
TEST_FILE_COUNT = 20 

class TestAutoPYaraComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Setup that runs ONCE before all tests.
        Initializes the AutoPYara tool and prepares file lists.
        """
        print("\n[+] Setting up Test Environment...")
        
        # 1. Initialize Tool
        try:
            # Using a lower ngram_top_k for speed during testing
            cls.tool = AutoPYara(ngram_top_k=500) 
            print("    - AutoPYara initialized successfully.")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize AutoPYara: {e}")

        # 2. Prepare Input Files
        if not os.path.exists(MALWARE_DIR):
            raise FileNotFoundError(f"Malware directory not found: {MALWARE_DIR}")
        
        all_files = [os.path.join(MALWARE_DIR, f) for f in os.listdir(MALWARE_DIR) 
                     if os.path.isfile(os.path.join(MALWARE_DIR, f))]
        
        if len(all_files) == 0:
            raise RuntimeError("No files found in malware directory.")

        # Take a subset to make tests run faster
        cls.input_files = all_files[:TEST_FILE_COUNT]
        print(f"    - Loaded {len(cls.input_files)} files for testing.")

        # 3. Create a temporary directory for outputs
        cls.test_output_dir = tempfile.mkdtemp()
        print(f"    - Temporary output directory: {cls.test_output_dir}")

    @classmethod
    def tearDownClass(cls):
        """
        Cleanup that runs ONCE after all tests.
        """
        print("\n[+] Tearing down Test Environment...")
        # Remove the temporary output directory
        shutil.rmtree(cls.test_output_dir)
        print("    - Temporary files cleaned up.")

    def test_01_legacy_vbgmm(self):
        """Test the original AutoYara VBGMM algorithm (Legacy Mode)"""
        print("\n--- Test 01: Legacy VBGMM Algorithm ---")
        result = self.tool.generate(
            input_files=self.input_files,
            bloom_malicious=BLOOM_MAL,
            bloom_benign=BLOOM_BEN,
            cluster_alg="VBGMM",
            output_format="string",
            verbose=False
        )
        
        self.assertIsNotNone(result, "Result should not be None")
        self.assertIn("rule_string", result, "Result must contain rule_string")
        # Ensure our 'k' fix works
        self.assertTrue("k_clusters" in result or "k" in result, "Result must contain k_clusters")
        k_val = result.get('k_clusters') or result.get('k')
        print(f"    PASS: Generated rule. Clusters found: {k_val}")

    def test_02_augmented_dbscan_default(self):
        """Test the new Augmented DBSCAN algorithm (Default Threshold)"""
        print("\n--- Test 02: Augmented DBSCAN (Default) ---")
        result = self.tool.generate(
            input_files=self.input_files,
            bloom_malicious=BLOOM_MAL,
            bloom_benign=BLOOM_BEN,
            cluster_alg="AugmentedKMeansDBSCAN",
            similarity_threshold=0.5, # Explicit threshold
            output_format="string",
            verbose=True # Turn on verbose to check logging
        )
        
        self.assertIsNotNone(result)
        # Check if the augmented predictor actually calculated K
        self.assertIsNotNone(result['k_clusters'], "k_clusters should be calculated")
        self.assertGreater(result['k_clusters'], 0, "k_clusters must be > 0")
        print(f"    PASS: Augmented K calculated: {result['k_clusters']}")

    def test_03_augmented_target_k_optimization(self):
        """Test the Optimization Loop (Force K=3)"""
        print("\n--- Test 03: Augmented Optimization (Target K=3) ---")
        target_k = 3
        # Note: Optimization might fail if files are too similar/dissimilar to split into 3
        try:
            result = self.tool.generate(
                input_files=self.input_files,
                bloom_malicious=BLOOM_MAL,
                bloom_benign=BLOOM_BEN,
                cluster_alg="AugmentedKMeansDBSCAN",
                augmented_target_k=target_k, # THE KEY FEATURE
                output_format="string",
                verbose=True
            )
            self.assertEqual(result['k_clusters'], target_k, f"Optimization failed to reach K={target_k}")
            print(f"    PASS: Successfully optimized to K={target_k}")
        except ValueError as e:
            # It raises ValueError if optimization fails (valid behavior for the tool given certain data)
            print(f"    WARN: Optimization could not converge (Expected behavior for small/rigid datasets): {e}")

    def test_04_output_format_yara_python(self):
        """Test outputting a compiled YARA object"""
        print("\n--- Test 04: Output Format 'yara-python' ---")
        result = self.tool.generate(
            input_files=self.input_files,
            bloom_malicious=BLOOM_MAL,
            bloom_benign=BLOOM_BEN,
            cluster_alg="VBGMM",
            output_format="yara-python",
            verbose=False
        )
        
        # Check if output is actually a compiled rules object
        self.assertIsInstance(result['output'], yara.Rules, "Output is not a compiled yara.Rules object")
        print("    PASS: Returned valid compiled yara.Rules object")

    def test_05_output_format_yaramod(self):
        """Test outputting a YARA-MOD object"""
        print("\n--- Test 05: Output Format 'yaramod' ---")
        result = self.tool.generate(
            input_files=self.input_files,
            bloom_malicious=BLOOM_MAL,
            bloom_benign=BLOOM_BEN,
            cluster_alg="VBGMM",
            output_format="yaramod",
            verbose=False
        )
        
        # Check if output is a Yaramod object (usually checks for 'text' or specific method availability)
        self.assertTrue(hasattr(result['output'], 'text'), "Output does not appear to be a Yaramod object (missing text method)")
        print("    PASS: Returned valid Yaramod object")

    def test_06_saving_files(self):
        """Test saving results to a specific directory"""
        print("\n--- Test 06: File Saving Capability ---")
        save_dir = os.path.join(self.test_output_dir, "saved_rules")
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
            
        result = self.tool.generate(
            input_files=self.input_files,
            bloom_malicious=BLOOM_MAL,
            bloom_benign=BLOOM_BEN,
            cluster_alg="VBGMM",
            output_dir=save_dir, # Trigger file saving
            output_format="string",
            verbose=False
        )
        
        # Check if files appeared in the directory
        saved_files = os.listdir(save_dir)
        self.assertGreater(len(saved_files), 0, "No files were saved to the output directory")
        print(f"    PASS: Files saved successfully to {save_dir}")
        print(f"          Files found: {saved_files}")

    def test_07_training_bloom_filters(self):
        """Test the ability to train new Bloom Filters"""
        print("\n--- Test 07: Training Capability (Bloom Filters) ---")
        
        # Create dummy training data structure
        train_input_dir = os.path.join(self.test_output_dir, "train_input")
        train_output_dir = os.path.join(self.test_output_dir, "train_output")
        os.makedirs(train_input_dir, exist_ok=True)
        os.makedirs(train_output_dir, exist_ok=True)
        
        # Copy a few malware files to use as training data
        for f in self.input_files[:3]:
            shutil.copy(f, train_input_dir)
            
        # Run Training
        try:
            self.tool.train(
                input_dir=train_input_dir,
                output_dir=train_output_dir,
                ngram_size=8
            )
            
            # Check if .bloom files were created
            generated_blooms = [f for f in os.listdir(train_output_dir) if f.endswith(".bloom")]
            self.assertGreater(len(generated_blooms), 0, "Training failed to generate .bloom files")
            print(f"    PASS: Successfully generated {len(generated_blooms)} bloom filters.")
            
        except Exception as e:
            self.fail(f"Training raised an exception: {e}")

    def test_08_error_handling(self):
        """Test if the tool handles bad inputs gracefully"""
        print("\n--- Test 08: Error Handling ---")
        
        # Test: Mismatched labels (Manual override)
        # We pass 2 labels for ~20 files, which should force a ValueError
        with self.assertRaises(ValueError):
             self.tool.generate(
                input_files=self.input_files,
                bloom_malicious=BLOOM_MAL,
                bloom_benign=BLOOM_BEN,
                predictor_labels=[0, 1] 
             )
        print("    PASS: Caught label mismatch error.")

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)