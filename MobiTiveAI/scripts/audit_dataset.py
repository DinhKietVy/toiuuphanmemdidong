
import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data" / "processed" / "extracted"

LABELS = {
    "benign": 0,
    "malware": 1,
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_api_calls(data):
    dex = data.get("dex_features", {})
    return dex.get("api_calls", []) or []


def get_manifest_features(data):
    manifest = data.get("manifest_features", {})
    return {
        "permissions": manifest.get("permissions", []) or [],
        "intents": manifest.get("intents", []) or [],
        "hardware": (
            manifest.get("hardware_features", [])
            or manifest.get("hardware", [])
            or []
        ),
    }


def main():
    all_samples = []
    sha_to_labels = defaultdict(set)
    package_to_labels = defaultdict(set)
    errors = []

    print("=" * 65)
    print("DATASET QUALITY AUDIT")
    print("=" * 65)

    for label_name, label_id in LABELS.items():
        folder = DATA_DIR / label_name
        files = sorted(folder.glob("*.json")) if folder.exists() else []

        print(f"\n[{label_name.upper()}] JSON files: {len(files)}")

        for path in files:
            try:
                data = load_json(path)

                metadata = data.get("metadata", {})
                sha256 = metadata.get("sha256") or path.stem
                package = metadata.get("package_name", "unknown")

                api_calls = get_api_calls(data)
                manifest = get_manifest_features(data)

                permission_count = len(manifest["permissions"])
                intent_count = len(manifest["intents"])
                hardware_count = len(manifest["hardware"])
                api_count = len(api_calls)

                record = {
                    "file": path.name,
                    "label": label_name,
                    "sha256": sha256,
                    "package": package,
                    "api_count": api_count,
                    "permission_count": permission_count,
                    "intent_count": intent_count,
                    "hardware_count": hardware_count,
                }

                all_samples.append(record)
                sha_to_labels[sha256].add(label_name)
                package_to_labels[package].add(label_name)

            except Exception as e:
                errors.append({
                    "file": str(path),
                    "error": str(e),
                })

    # Tổng hợp
    print("\n" + "=" * 65)
    print("FEATURE STATISTICS")
    print("=" * 65)

    for label_name in LABELS:
        samples = [x for x in all_samples if x["label"] == label_name]

        if not samples:
            continue

        print(f"\n{label_name.upper()}: {len(samples)} samples")

        for field in [
            "api_count",
            "permission_count",
            "intent_count",
            "hardware_count",
        ]:
            values = [x[field] for x in samples]
            nonzero = sum(v > 0 for v in values)

            print(
                f"  {field}: "
                f"min={min(values)}, "
                f"max={max(values)}, "
                f"mean={sum(values) / len(values):.2f}, "
                f"zero={len(values) - nonzero}"
            )

    # Trùng SHA256 giữa hai nhãn
    duplicate_sha = {
        sha: labels
        for sha, labels in sha_to_labels.items()
        if len(labels) > 1
    }

    # Package xuất hiện ở cả hai nhãn
    duplicate_packages = {
        package: labels
        for package, labels in package_to_labels.items()
        if len(labels) > 1 and package != "unknown"
    }

    # Các sample không có đặc trưng
    empty_samples = [
        x for x in all_samples
        if (
            x["api_count"] == 0
            and x["permission_count"] == 0
            and x["intent_count"] == 0
            and x["hardware_count"] == 0
        )
    ]

    print("\n" + "=" * 65)
    print("DATA QUALITY ISSUES")
    print("=" * 65)

    print(f"Total valid JSON: {len(all_samples)}")
    print(f"Invalid JSON/read errors: {len(errors)}")
    print(f"Duplicate SHA256 across labels: {len(duplicate_sha)}")
    print(f"Packages appearing in both labels: {len(duplicate_packages)}")
    print(f"Samples with all feature groups empty: {len(empty_samples)}")

    if duplicate_sha:
        print("\nDuplicate SHA256 examples:")
        for sha, labels in list(duplicate_sha.items())[:10]:
            print(f"  {sha}: {sorted(labels)}")

    if duplicate_packages:
        print("\nDuplicate package examples:")
        for package, labels in list(duplicate_packages.items())[:10]:
            print(f"  {package}: {sorted(labels)}")

    if empty_samples:
        print("\nEmpty feature examples:")
        for sample in empty_samples[:10]:
            print(f"  {sample['label']}/{sample['file']}")

    # Lưu báo cáo
    report_dir = ROOT_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "total_valid_json": len(all_samples),
        "invalid_json": errors,
        "duplicate_sha256_across_labels": {
            sha: sorted(labels)
            for sha, labels in duplicate_sha.items()
        },
        "duplicate_packages_across_labels": {
            package: sorted(labels)
            for package, labels in duplicate_packages.items()
        },
        "empty_samples": empty_samples,
        "samples": all_samples,
    }

    output = report_dir / "dataset_audit.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\nAudit report: {output}")
    print("\nAUDIT COMPLETED")


if __name__ == "__main__":
    main()
