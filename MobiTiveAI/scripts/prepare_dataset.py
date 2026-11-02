
import json
import hashlib
from pathlib import Path
from collections import Counter

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold


# ============================================================
# CONFIG
# ============================================================

ROOT_DIR = Path(__file__).resolve().parent.parent

INPUT_DIR = ROOT_DIR / "data" / "processed" / "extracted"
OUTPUT_DIR = ROOT_DIR / "data" / "processed" / "dataset"
METADATA_DIR = ROOT_DIR / "artifacts" / "metadata"

LABELS = {
    "benign": 0,
    "malware": 1,
}

TARGET_API_FEATURES = 2290
TARGET_MANIFEST_FEATURES = 625

RANDOM_STATE = 42


# ============================================================
# READ JSON
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_features(value):
    """
    Chuyển danh sách feature thành tập chuỗi duy nhất.
    Hỗ trợ list string và list dictionary.
    """
    result = set()

    def visit(item):
        if item is None:
            return

        if isinstance(item, str):
            item = item.strip()
            if item:
                result.add(item)

        elif isinstance(item, dict):
            for key, val in sorted(item.items()):
                if isinstance(val, (str, int, float, bool)):
                    result.add(f"{key}:{val}")
                elif isinstance(val, (list, dict)):
                    visit(val)

        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)

    visit(value)
    return result


def get_sample_features(data):
    dex = data.get("dex_features", {})
    manifest = data.get("manifest_features", {})

    api_features = normalize_features(
        dex.get("api_calls", [])
    )

    permission_features = normalize_features(
        manifest.get("permissions", [])
    )

    intent_features = normalize_features(
        manifest.get("intents", [])
    )

    hardware_features = normalize_features(
        manifest.get("hardware_features", [])
        or manifest.get("hardware", [])
    )

    manifest_features = set()

    manifest_features.update(
        f"permission:{x}" for x in permission_features
    )

    manifest_features.update(
        f"intent:{x}" for x in intent_features
    )

    manifest_features.update(
        f"hardware:{x}" for x in hardware_features
    )

    metadata = data.get("metadata", {})

    package_name = (
        metadata.get("package_name")
        or metadata.get("package")
        or "unknown"
    )

    sha256 = (
        metadata.get("sha256")
        or data.get("sha256")
        or ""
    )

    return {
        "api_features": api_features,
        "manifest_features": manifest_features,
        "package_name": package_name,
        "sha256": sha256,
    }


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():
    samples = []

    for label_name, label_id in LABELS.items():
        folder = INPUT_DIR / label_name

        if not folder.exists():
            raise FileNotFoundError(
                f"Không tìm thấy thư mục: {folder}"
            )

        files = sorted(folder.glob("*.json"))

        for path in files:
            data = load_json(path)
            features = get_sample_features(data)

            if not features["sha256"]:
                # Fallback nếu JSON không lưu SHA256.
                features["sha256"] = path.stem

            samples.append({
                "file": path.name,
                "label_name": label_name,
                "label": label_id,
                **features,
            })

    if not samples:
        raise RuntimeError("Dataset không có mẫu nào.")

    return samples


# ============================================================
# SPLIT DATASET BY PACKAGE
# ============================================================

def split_dataset(samples):
    y = np.array([x["label"] for x in samples])

    groups = np.array([
        x["package_name"]
        if x["package_name"] != "unknown"
        else x["sha256"]
        for x in samples
    ])

    # Outer split: 1 fold test, 4 folds còn lại train + validation.
    outer = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    train_val_idx, test_idx = next(
        outer.split(np.zeros(len(y)), y, groups)
    )

    # Inner split: 1/4 của phần còn lại làm validation.
    y_train_val = y[train_val_idx]
    groups_train_val = groups[train_val_idx]

    inner = StratifiedGroupKFold(
        n_splits=4,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    train_relative_idx, val_relative_idx = next(
        inner.split(
            np.zeros(len(train_val_idx)),
            y_train_val,
            groups_train_val,
        )
    )

    train_idx = train_val_idx[train_relative_idx]
    val_idx = train_val_idx[val_relative_idx]

    splits = {
        "train": train_idx,
        "validation": val_idx,
        "test": test_idx,
    }

    print("\nDATASET SPLIT")
    print("-" * 55)

    for name, indices in splits.items():
        labels = y[indices]

        benign_count = int(np.sum(labels == 0))
        malware_count = int(np.sum(labels == 1))

        print(
            f"{name:12s}: {len(indices):4d} samples | "
            f"Benign={benign_count} | "
            f"Malware={malware_count}"
        )

    return splits


# ============================================================
# BUILD FEATURE DICTIONARY FROM TRAIN ONLY
# ============================================================

def select_top_features(train_samples, feature_key, target_count):
    counter = Counter()

    for sample in train_samples:
        counter.update(sample[feature_key])

    # Sắp xếp theo document frequency giảm dần.
    # Nếu bằng nhau, sắp xếp tên feature để kết quả ổn định.
    ranked = sorted(
        counter.items(),
        key=lambda item: (-item[1], item[0])
    )

    selected = [
        feature
        for feature, frequency in ranked[:target_count]
    ]

    return selected, counter


def build_feature_dictionary(train_samples):
    api_features, api_counter = select_top_features(
        train_samples,
        "api_features",
        TARGET_API_FEATURES,
    )

    manifest_features, manifest_counter = select_top_features(
        train_samples,
        "manifest_features",
        TARGET_MANIFEST_FEATURES,
    )

    dictionary = {
        "version": "1.0",
        "selection_method": "training_document_frequency",
        "representation": "binary_presence",
        "api_features": api_features,
        "manifest_features": manifest_features,
        "api_feature_count": len(api_features),
        "manifest_feature_count": len(manifest_features),
        "total_feature_count": (
            len(api_features) + len(manifest_features)
        ),
        "target_api_features": TARGET_API_FEATURES,
        "target_manifest_features": TARGET_MANIFEST_FEATURES,
        "training_sample_count": len(train_samples),
        "api_unique_candidates": len(api_counter),
        "manifest_unique_candidates": len(manifest_counter),
    }

    return dictionary


# ============================================================
# VECTORIZE
# ============================================================

def vectorize_sample(sample, dictionary):
    api_index = {
        feature: i
        for i, feature in enumerate(dictionary["api_features"])
    }

    manifest_offset = len(dictionary["api_features"])

    manifest_index = {
        feature: manifest_offset + i
        for i, feature in enumerate(dictionary["manifest_features"])
    }

    total_features = dictionary["total_feature_count"]

    vector = np.zeros(total_features, dtype=np.float32)

    for feature in sample["api_features"]:
        index = api_index.get(feature)

        if index is not None:
            vector[index] = 1.0

    for feature in sample["manifest_features"]:
        index = manifest_index.get(feature)

        if index is not None:
            vector[index] = 1.0

    return vector


def save_split(name, samples, dictionary):
    X = np.array(
        [vectorize_sample(x, dictionary) for x in samples],
        dtype=np.float32,
    )

    y = np.array(
        [x["label"] for x in samples],
        dtype=np.int64,
    )

    np.save(OUTPUT_DIR / f"X_{name}.npy", X)
    np.save(OUTPUT_DIR / f"y_{name}.npy", y)

    metadata = []

    for sample in samples:
        metadata.append({
            "file": sample["file"],
            "label": sample["label"],
            "label_name": sample["label_name"],
            "package_name": sample["package_name"],
            "sha256": sample["sha256"],
        })

    with open(
        OUTPUT_DIR / f"samples_{name}.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print(
        f"{name}: X={X.shape}, y={y.shape}, "
        f"positive features={int(np.count_nonzero(X))}"
    )


# ============================================================
# MAIN
# ============================================================

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 65)
    print("MOBITIVE DATASET PREPARATION")
    print("=" * 65)

    samples = load_dataset()

    print(f"\nTotal samples loaded: {len(samples)}")

    splits = split_dataset(samples)

    train_samples = [
        samples[i] for i in splits["train"]
    ]

    # Dictionary chỉ được xây dựng từ train.
    dictionary = build_feature_dictionary(train_samples)

    dictionary_path = (
        METADATA_DIR / "feature_dictionary.json"
    )

    with open(
        dictionary_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            dictionary,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print("\nFEATURE DICTIONARY")
    print("-" * 55)
    print(f"API features:      {dictionary['api_feature_count']}")
    print(f"Manifest features: {dictionary['manifest_feature_count']}")
    print(f"Total features:    {dictionary['total_feature_count']}")
    print(f"API candidates:    {dictionary['api_unique_candidates']}")
    print(
        "Manifest candidates: "
        f"{dictionary['manifest_unique_candidates']}"
    )

    # Vector hóa từng tập bằng cùng một dictionary.
    for split_name, indices in splits.items():
        split_samples = [
            samples[i] for i in indices
        ]

        save_split(
            split_name,
            split_samples,
            dictionary,
        )

    # Lưu thông tin split và seed để tái lập.
    split_metadata = {
        "random_state": RANDOM_STATE,
        "split_method": "StratifiedGroupKFold",
        "group_key": "package_name",
        "splits": {
            name: [samples[i]["sha256"] for i in indices]
            for name, indices in splits.items()
        },
    }

    with open(
        METADATA_DIR / "dataset_splits.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            split_metadata,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print("\n" + "=" * 65)
    print("DATASET PREPARATION COMPLETED")
    print("=" * 65)
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"Feature dictionary: {dictionary_path}")


if __name__ == "__main__":
    main()
