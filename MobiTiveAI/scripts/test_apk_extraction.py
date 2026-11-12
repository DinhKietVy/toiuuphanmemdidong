
import sys
import json
import argparse

from pathlib import Path

# Thêm thư mục src vào Python path
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

sys.path.insert(0, str(SRC_DIR))

from mobitive.apk_parser import parse_apk
from mobitive.manifest_extractor import extract_manifest_features
from mobitive.dex_extractor import extract_api_calls


def main():

    parser = argparse.ArgumentParser(
        description="MobiTive APK Feature Extraction"
    )

    parser.add_argument(
        "apk_path",
        help="Đường dẫn tới file APK cần phân tích"
    )

    args = parser.parse_args()

    apk_path = Path(args.apk_path)

    print("=" * 60)
    print("MOBITIVE APK FEATURE EXTRACTION")
    print("=" * 60)

    # -----------------------------------
    # 1. Parse APK
    # -----------------------------------

    parsed = parse_apk(str(apk_path))

    apk = parsed["apk"]
    dex_list = parsed["dex_list"]
    metadata = parsed["metadata"]

    # -----------------------------------
    # 2. Extract Manifest
    # -----------------------------------

    print("\n[MANIFEST] Extracting features...")

    manifest_features = extract_manifest_features(apk)

    print(
        "Permissions:",
        len(manifest_features["permissions"])
    )

    print(
        "Intents:",
        len(manifest_features["intents"])
    )

    print(
        "Hardware features:",
        len(manifest_features["hardware_features"])
    )

    # -----------------------------------
    # 3. Extract DEX API calls
    # -----------------------------------

    print("\n[DEX] Extracting API calls...")

    dex_features = extract_api_calls(apk_path)

    print(
        "Unique API calls:",
        dex_features["unique_api_call_count"]
    )

    print(
        "Method refs (method_ids):",
        dex_features["method_ref_count"]
    )

    # -----------------------------------
    # 4. Combine results
    # -----------------------------------

    result = {
        "metadata": metadata,

        "manifest_features": manifest_features,

        "dex_features": dex_features,
    }

    # -----------------------------------
    # 5. Save JSON
    # -----------------------------------

    output_dir = ROOT_DIR / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = (
        output_dir /
        f"{apk_path.stem}_features.json"
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            ensure_ascii=False,
            indent=4
        )

    print("\n" + "=" * 60)
    print("EXTRACTION COMPLETED")
    print("=" * 60)

    print("Package:", metadata["package_name"])
    print("SHA256:", metadata["sha256"])

    print("Permissions:",
          len(manifest_features["permissions"]))

    print("Intents:",
          len(manifest_features["intents"]))

    print("Hardware features:",
          len(manifest_features["hardware_features"]))

    print("Unique API calls:",
          dex_features["unique_api_call_count"])

    print("Output:", output_path)


if __name__ == "__main__":
    main()
