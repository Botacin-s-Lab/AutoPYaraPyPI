import jpype
from typing import Literal, List
import yara
import yaramod
import os
import sys
import contextlib
import re
from .interface import PythonInterface
from .augmented_predictor.DBSCAN_SSDEEP import AugmentedDBScan

BiclusterAlgorithmType = Literal['SpectralCoCluster', 'SpectralCoClusterScale']
ClusterAlgorithmType = Literal[
    'VBGMM', 'KMeans', 'KMeansSoft', 'Random',
    'AugmentedKMeansDBSCAN', 'AugmentedKMeansDBSCANSoft',
    'AugmentedKMeansVT', 'AugmentedKMeansVTSoft'
]
RuleOutputType = Literal['yara-python', 'yaramod', 'string']
SelectionHeuristic = Literal['AutoYara', 'PYara']

augmented_algorithms = ['AugmentedKMeansDBSCAN', 'AugmentedKMeansDBSCANSoft', 'AugmentedKMeansVT', 'AugmentedKMeansVTSoft']

# --- CONTEXT MANAGER TO SUPPRESS JAVA LOGS ---
@contextlib.contextmanager
def suppress_output(suppress=True):
    if not suppress:
        yield
        return
    try:
        null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
        save_fds = [os.dup(1), os.dup(2)]
        os.dup2(null_fds[0], 1)
        os.dup2(null_fds[1], 2)
        yield
    finally:
        if suppress:
            os.dup2(save_fds[0], 1)
            os.dup2(save_fds[1], 2)
            for fd in null_fds + save_fds:
                os.close(fd)
# ---------------------------------------------

class AutoPYara(PythonInterface):
    def __init__(self, ngram_top_k=1000):
        super().__init__()
        self.AutoYaraCluster = jpype.JPackage("edu.lps.acs.ml.autoyara").AutoYaraCluster
        self.AutoYaraPython = jpype.JPackage("edu.lps.acs.ml.autoyara").AutoYaraPython
        self.Bytes2Bloom = jpype.JPackage("edu.lps.acs.ml.autoyara").Bytes2Bloom
        self.File = jpype.JClass("java.io.File")
        self.ArrayList = jpype.JClass("java.util.ArrayList")
        self.Integer = jpype.JClass("java.lang.Integer")

        self.yara_cluster_legacy = self.AutoYaraCluster()
        self.yara_cluster = self.AutoYaraPython()
        self.bytes2bloom = self.Bytes2Bloom()

        self.yara_cluster.max_filter_size = 10000000
        self.yara_cluster_legacy.max_filter_size = 10000000
        self.bytes2bloom.tooKeep = ngram_top_k
        self.yaramod = yaramod.Yaramod(yaramod.Features.AllCurrent)
        
        # [SETUP] Internal Paths for Flag Resolution
        self.pkg_path = os.path.dirname(__file__)
        self.data_path = os.path.join(self.pkg_path, 'data')
        self.blooms_path = os.path.join(self.data_path, 'blooms')

    def build_candidate_set(self, target_dir, bloom_mal_dir, bloom_beg_dir, ngram_size=8):
        return self.yara_cluster.buildCandidateSet(
            self.File(target_dir), ngram_size, self.File(bloom_beg_dir), self.File(bloom_mal_dir))

    def train(self, input_dir, output_dir, ngram_size=8):
        input_file = self.File(input_dir)
        output_file = self.File(output_dir)
        self.bytes2bloom.inDir = input_file
        self.bytes2bloom.gramSizes = self.ArrayList()
        self.bytes2bloom.gramSizes.add(self.Integer(ngram_size))
        self.bytes2bloom.outDir = output_file
        try:
            print("Starting bloom filter training")
            self.bytes2bloom.run()
            print(f"{ngram_size}-gram extraction complete for {input_dir}")
        except Exception as e:
            print(f"Exception during {ngram_size}-gram extraction: {e}")
        self.reset_memory()

    def generate(self, input_files, bloom_malicious, bloom_benign,
             output_dir=None,
             bicluster_alg: BiclusterAlgorithmType = 'SpectralCoCluster', 
             cluster_alg: ClusterAlgorithmType = 'VBGMM',
             output_format: RuleOutputType = 'string', 
             predictor_labels=None, 
             k_cluster=0, 
             similarity_threshold=None,
             rule_name=None, 
             selection_heuristic: SelectionHeuristic = "PYara", 
             bicluster_feature_prune_coverage=50,
             augmented_target_k=None,
             verbose=False):

        # ==============================================================================
        # [SMART FLAG HANDLING]
        # Uses global 'os' module (Shadowing fixed)
        # ==============================================================================
        if isinstance(bloom_malicious, str):
            flag = bloom_malicious.lower()
            
            # FLAG 1: "ember" -> Points to .../data/blooms/ember/
            if flag == 'ember':
                if verbose: print(f"[AutoPYara] Flag '{flag}' detected. Switching to EMBER filters.")
                bloom_malicious = os.path.join(self.blooms_path, "ember", "malicious")
                bloom_benign    = os.path.join(self.blooms_path, "ember", "benign")

            # FLAG 2: "autopyara" -> Points to .../data/blooms/autopyara/
            elif flag == 'autopyara':
                if verbose: print(f"[AutoPYara] Flag '{flag}' detected. Switching to DEFAULT (AutoPYara) filters.")
                bloom_malicious = os.path.join(self.blooms_path, "autopyara", "malicious")
                bloom_benign    = os.path.join(self.blooms_path, "autopyara", "benign")
            
            # FLAG 3: Custom Path (User Provided) -> Keep as is
            else:
                pass 
                
            # SANITY CHECK
            if bloom_malicious and not os.path.exists(bloom_malicious):
                print(f"[!] WARNING: The resolved filter path does not exist:")
                print(f"    {bloom_malicious}")
        # ==============================================================================

        # --- 1. PREPARE RULE NAME ---
        base_name = "autoyara_rule"
        if rule_name:
            clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
            if clean_name and clean_name[0].isdigit():
                clean_name = "rule_" + clean_name
            base_name = clean_name

        input_files_list = self.ArrayList()
        if isinstance(input_files, str):
            # [FIX] Removed internal 'import os' here to prevent UnboundLocalError
            if os.path.isdir(input_files):
                 for f in os.listdir(input_files):
                      input_files_list.add(self.File(os.path.join(input_files, f)))
            else:
                 input_files_list.add(self.File(input_files))
        else:
            for file_path in input_files:
                input_files_list.add(self.File(file_path))
                
        self.yara_cluster.inDir = input_files_list
        self.yara_cluster.biclusterPipelineAlg = bicluster_alg
        self.yara_cluster.clusterAlg = cluster_alg
        self.yara_cluster.benign_bloom_dir = self.File(bloom_benign)
        self.yara_cluster.malicious_bloom_dir = self.File(bloom_malicious)
        self.yara_cluster.selectionHeuristic = selection_heuristic
        self.yara_cluster.biclusterFeaturePruneCoverage = bicluster_feature_prune_coverage/100
        self.yara_cluster.name = base_name
        
        if k_cluster: self.yara_cluster.k = k_cluster
        if output_dir: self.yara_cluster.out_dir = output_dir

        self.yara_cluster.findBestRulePipelineInit()

        # AUGMENTED K CALCULATION
        calculated_k = None
        if cluster_alg in augmented_algorithms and not predictor_labels:
            if k_cluster: raise ValueError("you cannot specify k clusters for Augmented Learning clustering")
            
            targets = self.convert_java_to_python(self.yara_cluster.targets)
            augmented_predictor = AugmentedDBScan(dbscan_threshold=similarity_threshold, augmented_target_k=augmented_target_k)
            predictor_labels = augmented_predictor.predict(targets)
            
            self.yara_cluster.k = len(set(predictor_labels))
            calculated_k = self.yara_cluster.k
            if verbose:
                print("PYARA: calculated k =", self.yara_cluster.k)

        if predictor_labels:
            if len(predictor_labels) != len(self.yara_cluster.targets):
                raise ValueError(f"Label mismatch: {len(predictor_labels)} != {len(self.yara_cluster.targets)}")
            self.yara_cluster.predictorLabels = predictor_labels

        try:
            with suppress_output(suppress=not verbose):
                yara_out = dict(self.yara_cluster.pythonRun())
            
            yara_out = self.convert_java_to_python(yara_out)

            final_k = None
            if calculated_k is not None: final_k = calculated_k
            elif 'k_clusters' in yara_out: final_k = yara_out['k_clusters']
            elif 'k' in yara_out: final_k = yara_out['k']
            elif 'K' in yara_out: final_k = yara_out['K']
            elif 'bestK' in yara_out: final_k = yara_out['bestK']
            elif self.yara_cluster.k and self.yara_cluster.k > 0: final_k = self.yara_cluster.k
            
            yara_out['k'] = final_k
            yara_out['k_clusters'] = final_k

            self.yara_cluster.resetYaraState()
            
            rule_str = yara_out.get('rule_string', '')
            if rule_str:
                rule_str = re.sub(r'rule\s+(\d+)', f'rule {base_name}_\\1', rule_str)
                yara_out['rule_string'] = rule_str

            if output_format == "string": 
                yara_out["output"] = rule_str
            elif output_format == "yara-python": 
                yara_out["output"] = yara.compile(source=rule_str)
            elif output_format == "yaramod": 
                yara_out["output"] = self.yaramod.parse_string(rule_str)
            
            self.reset_memory()
            return yara_out
        except Exception as e:
            self.yara_cluster.resetYaraState()
            self.reset_memory()
            if verbose: print(f"Exception during run: {e}")
            raise e