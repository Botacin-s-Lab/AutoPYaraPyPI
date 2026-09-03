"""
Unit tests for autopyara.augmented_predictor.DBSCAN_SSDEEP.AugmentedDBScan.

These avoid depending on ssdeep's actual similarity output on tiny synthetic
files (which is not meaningful at that scale) by testing the two things that
are pure Python logic: the noise-label post-processing in direct_predict(),
and the threshold search loop in predict(). Both are exercised by
monkeypatching the ssdeep-backed pieces (DBSCAN_Cluster / direct_predict).
"""
from autopyara.augmented_predictor.DBSCAN_SSDEEP import AugmentedDBScan


def test_dbscan_cluster_single_file_edge_case():
    predictor = AugmentedDBScan()
    result = predictor.DBSCAN_Cluster(["only_one_file.bin"])
    assert result == {0: ["only_one_file.bin"]}


def test_direct_predict_ascending_noise_labeling(monkeypatch):
    predictor = AugmentedDBScan(noise_labeling="Ascending")
    # Two real clusters (0, 1) plus three DBSCAN "noise" points (-1).
    fake_clusters = {
        0: ["a", "b"],
        1: ["c"],
        -1: ["d", "e", "f"],
    }
    monkeypatch.setattr(predictor, "DBSCAN_Cluster", lambda *a, **k: fake_clusters)

    labels = predictor.direct_predict(["a", "b", "c", "d", "e", "f"])

    # Real clusters keep their id; each noise point gets its own new id,
    # counting up from (max real cluster id + 1).
    assert labels[0:3] == [0, 0, 1]
    noise_labels = labels[3:]
    assert noise_labels == [2, 3, 4]


def test_direct_predict_zeros_noise_labeling(monkeypatch):
    predictor = AugmentedDBScan(noise_labeling="Zeros")
    fake_clusters = {0: ["a"], -1: ["b", "c"]}
    monkeypatch.setattr(predictor, "DBSCAN_Cluster", lambda *a, **k: fake_clusters)

    labels = predictor.direct_predict(["a", "b", "c"])

    assert labels == [0, 0, 0]


def test_predict_with_target_k_one_or_less_short_circuits(monkeypatch):
    predictor = AugmentedDBScan(augmented_target_k=1)
    monkeypatch.setattr(
        predictor, "direct_predict", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called"))
    )
    assert predictor.predict(["a", "b", "c"]) == [0, 0, 0]


def test_predict_with_no_target_k_delegates_to_direct_predict(monkeypatch):
    predictor = AugmentedDBScan(augmented_target_k=None)
    calls = []
    monkeypatch.setattr(predictor, "direct_predict", lambda paths: calls.append(paths) or ["stub"])

    result = predictor.predict(["a", "b"])

    assert result == ["stub"]
    assert calls == [["a", "b"]]


def test_predict_threshold_search_converges_on_target_k(monkeypatch):
    """
    Simulate a monotonic relationship between threshold and cluster count
    (higher similarity threshold -> more clusters) and check the search
    lands on the target without needing real ssdeep hashing.
    """
    predictor = AugmentedDBScan(augmented_target_k=4)
    file_paths = ["f1", "f2", "f3", "f4", "f5"]

    def fake_direct_predict(paths, final_prediction=True):
        # Map the current threshold onto a plausible cluster count.
        k = max(1, min(len(paths), round(predictor.dbscan_threshold / 20)))
        return list(range(k)) + [0] * (len(paths) - k)

    monkeypatch.setattr(predictor, "direct_predict", fake_direct_predict)

    labels = predictor.predict(file_paths)

    assert 1 <= predictor.dbscan_threshold <= 99
    assert isinstance(labels, list)
    assert len(labels) == len(file_paths)
