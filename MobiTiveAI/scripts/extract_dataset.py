
import sys
import json
import csv
import hashlib
import traceback
from pathlib import Path
from datetime import datetime

# ==========================================
# PROJECT CONFIGURATION
# ==========================================

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

sys.path.insert(0, str(SRC_DIR))

from mobitive.apk_parser import parse_apk
from mobitive.manifest_extractor import extract_manifest_features
from mobitive.dex_extractor import extract_api_calls

RAW_DIR = ROOT_DIR / "data" / "raw"
PROCESSED_DIR = ROOT_DIR / "data" / "processed" / "extracted"
REPORT_DIR = ROOT_DIR / "reports"

CLASSES = {
    "benign": 0,
    "malware": 1
}

# Nếu True, bỏ qua JSON đã tồn tại.
SKIP_EXISTING = True

# ==========================================
# DIRECTORY SETUP
# ==========================================

for label in CLASSES:
    (PROCESSED_DIR / label).mkdir(parents=True, exist_ok=True)

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================
# HASH
# ==========================================

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ==========================================
# EXTRACT ONE APK
# ==========================================

def extract_one_apk(apk_path, label):
    print(f"\n[APK] {apk_path.name}")

    # 1. Parse APK
    parsed = parse_apk(str(apk_path))

    apk = parsed["apk"]
    dex_list = parsed["dex_list"]
    metadata = parsed["metadata"]

    # 2. Extract Manifest
    print("[MANIFEST] Extracting...")

    manifest_features = extract_manifest_features(apk)

    # 3. Extract DEX
    print("[DEX] Extracting...")

    dex_features = extract_api_calls(dex_list)

    # 4. Combine
    result = {
        "metadata": metadata,

        "label": label,
        "label_id": CLASSES[label],

        "source": str(apk_path.relative_to(ROOT_DIR)),

        "manifest_features": manifest_features,

        "dex_features": dex_features,

        "extraction": {
            "timestamp": datetime.now().isoformat(),
            "status": "success"
        }
    }

    # 5. Save JSON
    output_path = (
        PROCESSED_DIR
        / label
        / f"{metadata['sha256']}.json"
    )

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(
            result,
            file,
            ensure_ascii=False,
            indent=2
        )

    print(f"[SUCCESS] {apk_path.name}")
    print(f"  Package: {metadata['package_name']}")
    print(f"  Permissions: {len(manifest_features['permissions'])}")
    print(f"  Intents: {len(manifest_features['intents'])}")
    print(f"  Hardware: {len(manifest_features['hardware_features'])}")
    print(f"  API calls: {dex_features['unique_api_call_count']}")

    return {
        "file_name": apk_path.name,
        "sha256": metadata["sha256"],
        "package_name": metadata["package_name"],
        "label": label,
        "label_id": CLASSES[label],
        "file_size": metadata["file_size"],
        "permission_count": len(manifest_features["permissions"]),
        "intent_count": len(manifest_features["intents"]),
        "hardware_feature_count": len(manifest_features["hardware_features"]),
        "api_call_count": dex_features["unique_api_call_count"],
        "invoke_instruction_count": dex_features["invoke_instruction_count"],
        "status": "success",
        "output_path": str(output_path)
    }


# ==========================================
# GET APK FILES
# ==========================================

def get_apk_files(label):
    folder = RAW_DIR / label

    if not folder.exists():
        print(f"[WARNING] Folder does not exist: {folder}")
        return []

    return sorted(folder.rglob("*.apk"))


# ==========================================
# SAVE CSV REPORTS
# ==========================================

def save_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


# ==========================================
# PROCESS DATASET
# ==========================================

def process_dataset():
    summary = []
    errors = []

    total_processed = 0
    total_skipped = 0
    total_failed = 0

    for label in CLASSES:

        apk_files = get_apk_files(label)

        print("\n" + "=" * 65)
        print(f"PROCESSING CLASS: {label.upper()}")
        print(f"TOTAL APK FILES: {len(apk_files)}")
        print("=" * 65)

        for index, apk_path in enumerate(apk_files, start=1):

            print(f"\n[{index}/{len(apk_files)}]")

            try:
                # Calculate hash before processing
                sha256 = calculate_sha256(apk_path)

                output_path = (
                    PROCESSED_DIR
                    / label
                    / f"{sha256}.json"
                )

                # Skip previously processed APK
                if SKIP_EXISTING and output_path.exists():

                    total_skipped += 1

                    print(f"[SKIP] Already processed: {apk_path.name}")

                    continue

                result = extract_one_apk(apk_path, label)

                summary.append(result)
                total_processed += 1

            except Exception as error:

                total_failed += 1

                error_info = {
                    "file_name": apk_path.name,
                    "file_path": str(apk_path),
                    "label": label,
                    "error": str(error),
                    "error_type": type(error).__name__
                }

                errors.append(error_info)

                print(f"[ERROR] {apk_path.name}")
                print(f"Reason: {error}")

    # ======================================
    # SAVE REPORTS
    # ======================================

    summary_path = REPORT_DIR / "extraction_summary.csv"
    errors_path = REPORT_DIR / "extraction_errors.csv"

    summary_fields = [
        "file_name",
        "sha256",
        "package_name",
        "label",
        "label_id",
        "file_size",
        "permission_count",
        "intent_count",
        "hardware_feature_count",
        "api_call_count",
        "invoke_instruction_count",
        "status",
        "output_path"
    ]

    error_fields = [
        "file_name",
        "file_path",
        "label",
        "error",
        "error_type"
    ]

    save_csv(summary_path, summary, summary_fields)
    save_csv(errors_path, errors, error_fields)

    # ======================================
    # FINAL SUMMARY
    # ======================================

    print("\n" + "=" * 65)
    print("DATASET EXTRACTION COMPLETED")
    print("=" * 65)

    print(f"Newly processed: {total_processed}")
    print(f"Skipped: {total_skipped}")
    print(f"Failed: {total_failed}")

    print(f"\nBenign JSON: {len(list((PROCESSED_DIR / 'benign').glob('*.json')))}")
    print(f"Malware JSON: {len(list((PROCESSED_DIR / 'malware').glob('*.json')))}")

    print(f"\nSummary: {summary_path}")
    print(f"Errors: {errors_path}")


if __name__ == "__main__":
    process_dataset()
