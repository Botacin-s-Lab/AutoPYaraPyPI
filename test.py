import os
from autopyara import AutoPYara

# --- CONFIGURATION ---
malware_dir = "/mnt/data/stanic_copy/malware/MLSec21"
custom_bloom_mal = "/home/mtech-server/RetrainedBloomFilters/malicious/"
custom_bloom_ben = "/home/mtech-server/RetrainedBloomFilters/benign/"

# Get list of files
input_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir) 
               if os.path.isfile(os.path.join(malware_dir, f))]

# Limit files for faster testing if needed (optional)
# input_files = input_files[:20] 

print(f"[*] Loaded {len(input_files)} malware samples.")

# Initialize Tool
tool = AutoPYara()

# Define test cases: (Bloom Name, Malicious Path, Benign Path)
bloom_configs = [
    ("EMBER (Built-in)", "ember", "ember"),
    ("AutoPYara (Built-in)", "autopyara", "autopyara"),
    ("Custom (Retrained)", custom_bloom_mal, custom_bloom_ben)
]

print("\n========================================")
print("   STARTING COMPREHENSIVE TEST SUITE   ")
print("========================================\n")

for config_name, bloom_mal, bloom_ben in bloom_configs:
    print(f"\n>>> TESTING CONFIG: {config_name}")
    print(f"    Bloom Mal: {bloom_mal}")
    print(f"    Bloom Ben: {bloom_ben}")
    print("-" * 40)

    # ---------------------------------------------------------
    # TEST 1: PRESET = AutoYara (Manual K / Standard)
    # ---------------------------------------------------------
    print(f"  [Test 1] Preset='AutoYara' (VBGMM + Manual K=3)")
    try:
        res_standard = tool.generate(
            input_files=input_files,
            bloom_malicious=bloom_mal,
            bloom_benign=bloom_ben,
            preset="AutoYara",     # <--- Uses VBGMM + AutoYara Heuristic
            k_cluster=3,           # <--- We MUST provide K or rely on VBGMM defaults
            output_format="string",
            verbose=False
        )
        print(f"    SUCCESS: Generated rule with k={res_standard.get('k_clusters')}")
        # print(res_standard['output'][:100] + "...") # Print snippet if needed
    except Exception as e:
        print(f"    FAILED: {e}")

    # ---------------------------------------------------------
    # TEST 2: PRESET = AutoPYara (Auto-K / Augmented)
    # ---------------------------------------------------------
    print(f"  [Test 2] Preset='AutoPYara' (Augmented + Auto-K)")
    try:
        res_augmented = tool.generate(
            input_files=input_files,
            bloom_malicious=bloom_mal,
            bloom_benign=bloom_ben,
            preset="AutoPYara",    # <--- Uses AugmentedKMeansDBSCANSoft + PYara Heuristic
            # Note: No k_cluster provided here, it should auto-calculate!
            output_format="string",
            verbose=False
        )
        print(f"    SUCCESS: Auto-calculated k={res_augmented.get('k_clusters')}")
        # print(res_augmented['output'][:100] + "...")
    except Exception as e:
        print(f"    FAILED: {e}")

    # ---------------------------------------------------------
    # TEST 3: TARGETED K (Augmented + Target K=4)
    # ---------------------------------------------------------
    print(f"  [Test 3] Preset='AutoPYara' + Target K=4")
    try:
        res_target = tool.generate(
            input_files=input_files,
            bloom_malicious=bloom_mal,
            bloom_benign=bloom_ben,
            preset="AutoPYara",
            augmented_target_k=4, # <--- Force the optimizer to find 4 clusters
            output_format="string",
            verbose=False
        )
        print(f"    SUCCESS: Optimized for Target K=4 -> Result k={res_target.get('k_clusters')}")
    except Exception as e:
        print(f"    FAILED: {e}")

print("\n========================================")
print("           TEST SUITE COMPLETE          ")
print("========================================")