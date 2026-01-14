import numpy as np
from sklearn.cluster import DBSCAN
import ppdeep as ssdeep  # Using ppdeep for easier pip installation
import sys, os
from typing import Literal

# noise labeling:
# Zeroes: samples not grouped by DBSCAN
NoiseLabelling = Literal['Zeros', 'Ascending']

def java_to_python_paths(paths):
    """Helper to ensure paths are strings, not Java Objects."""
    clean_paths = []
    for p in paths:
        # If it's a Java File object, get path, otherwise string
        if hasattr(p, 'getPath'):
            clean_paths.append(str(p.getPath()))
        else:
            clean_paths.append(str(p))
    return clean_paths

class AugmentedDBScan():
    def __init__(self, epsilon=0.5, min_samples=5, dbscan_threshold=90, augmented_target_k=None, noise_labeling: NoiseLabelling = 'Ascending'):
        self.epsilon = epsilon
        self.min_samples = min_samples
        self.noise_labeling = noise_labeling
        self.dbscan_threshold = dbscan_threshold

        self.augmented_target_k = augmented_target_k

        if not dbscan_threshold and not augmented_target_k:
            self.augmented_target_k = 2

    def DBSCAN_Cluster(self, file_paths, similarity_threshold=80, min_samples=2):
        n_files = len(file_paths)

        if n_files < 2:
            # Handle edge case where we only have 1 file
            return {0: file_paths}

        if similarity_threshold >= 100:
            similarity_threshold = 99.9 

        # Compute ssdeep hashes
        hashes = {}
        for file in file_paths:
            try:
                hashes[file] = ssdeep.hash_from_file(file)
            except Exception:
                # Fallback for empty/locked files
                hashes[file] = None

        # Build distance matrix
        distance_matrix = np.zeros((n_files, n_files))

        for i in range(n_files):
            for j in range(i + 1, n_files):
                h1 = hashes[file_paths[i]]
                h2 = hashes[file_paths[j]]
                
                if h1 and h2:
                    similarity = ssdeep.compare(h1, h2) / 100.0
                    distance = 1 - similarity
                else:
                    distance = 1.0 # Max distance if hash fails

                distance_matrix[i, j] = distance
                distance_matrix[j, i] = distance 

        # Configure DBSCAN
        eps = 1 - (similarity_threshold / 100.0)
        # Ensure eps is never exactly 0 to prevent DBSCAN errors
        if eps <= 0: eps = 0.001
        
        db = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed")
        labels = db.fit_predict(distance_matrix)

        # Group files by cluster
        clusters = {}
        for file, label in zip(file_paths, labels):
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(file)

        return clusters

    def direct_predict(self, file_paths, final_prediction=True):
        file_paths = java_to_python_paths(file_paths)

        if final_prediction:
            print(f"[*] Clustering {len(file_paths)} files with threshold {self.dbscan_threshold}...")

        clusters = self.DBSCAN_Cluster(
            file_paths,
            similarity_threshold=self.dbscan_threshold,
            min_samples=2,
        )

        path_to_cluster = {}
        
        # Calculate noise label start
        # DBSCAN noise is -1. We want to map it to unique IDs or a specific group.
        current_max_cluster = max(clusters.keys()) if clusters else 0
        noise_cluster_id = current_max_cluster + 1

        for cluster_num, paths in clusters.items():
            for path in paths:
                if cluster_num == -1: # Noise
                    if self.noise_labeling == "Zeros":
                        transformed_cluster_num = 0 # Or a specific noise bin
                    elif self.noise_labeling == "Ascending":
                        transformed_cluster_num = noise_cluster_id
                        noise_cluster_id += 1
                    else:
                        transformed_cluster_num = noise_cluster_id
                else:
                    transformed_cluster_num = cluster_num

                path_to_cluster[path] = transformed_cluster_num

        # Create the predictor_labels list in the same order as file_paths
        predictor_labels = [path_to_cluster[path] for path in file_paths]

        return predictor_labels

    def predict(self, file_paths):
        """
        Gradient-descent optimization to find threshold matching augmented_target_k.
        """
        if self.augmented_target_k is None:
            return self.direct_predict(file_paths)
        elif self.augmented_target_k <= 1:
            return [0] * len(file_paths)

        # Initial parameters
        current_threshold = 50
        learning_rate = 15.0 
        max_iterations = 20
        tolerance = 0.5 

        largest_error = 99999
        best_threshold = current_threshold
        best_clusters = 0

        print(f"[*] Optimizing Threshold for Target K={self.augmented_target_k}")

        for iteration in range(max_iterations):
            self.dbscan_threshold = current_threshold
            labels = self.direct_predict(file_paths, final_prediction=False)
            current_clusters = len(set(labels))

            error = current_clusters - self.augmented_target_k

            # Perfect match found?
            if abs(error) <= tolerance:
                best_threshold = current_threshold
                best_clusters = current_clusters
                break

            if abs(error) < largest_error:
                largest_error = abs(error)
                best_threshold = current_threshold
                best_clusters = current_clusters

            # Adjust Threshold
            # Too many clusters -> Increase similarity req (Threshold Up? No, wait)
            # Threshold is Similarity (0-100).
            # High Threshold = Strict = More fragments/small clusters? 
            # Low Threshold = Loose = Giant clusters (few clusters).
            
            # Logic check:
            # If we have TOO MANY clusters (error > 0), we are too strict. We need to LOWER threshold to merge them.
            # If we have TOO FEW clusters (error < 0), we are too loose. We need to RAISE threshold to split them.
            
            direction = 1 if error < 0 else -1 

            adaptive_rate = learning_rate * (1.0 / (iteration + 1))
            current_threshold += direction * adaptive_rate
            current_threshold = max(1, min(99, current_threshold))

            print(f"   Iter {iteration}: Thresh={current_threshold:.2f}, K={current_clusters}, Target={self.augmented_target_k}")

        print(f"[*] Final Opt: Threshold={best_threshold:.2f}, K={best_clusters}")
        self.dbscan_threshold = best_threshold
        return self.direct_predict(file_paths)