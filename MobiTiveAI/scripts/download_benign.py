
import csv
import hashlib
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from tqdm import tqdm

# =========================
# CONFIG
# =========================
PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_DIR / "data" / "raw" / "benign"
CSV_PATH = OUTPUT_DIR / "metadata.csv"

INDEX_URL = "https://f-droid.org/repo/index-v1.json"
APK_BASE_URL = "https://f-droid.org/repo/"

TARGET_COUNT = 500
MAX_WORKERS = 4
RANDOM_SEED = 42

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()



def load_index():
    print("[1/3] Downloading F-Droid index...")

    response = requests.get(INDEX_URL, timeout=120)
    response.raise_for_status()

    data = response.json()
    packages = data.get("packages", {})

    candidates = []

    for package_name, versions in packages.items():

        # Trong index-v1, versions là list
        if not isinstance(versions, list) or not versions:
            continue

        # Chọn phiên bản có versionCode lớn nhất
        latest = max(
            versions,
            key=lambda x: int(x.get("versionCode", 0))
        )

        apk_name = latest.get("apkName")
        expected_hash = latest.get("hash")
        hash_type = latest.get("hashType", "sha256").lower()

        if not apk_name or not expected_hash:
            continue

        # Chỉ chấp nhận SHA256
        if hash_type != "sha256" or len(expected_hash) != 64:
            continue

        candidates.append({
            "package_name": package_name,
            "apk_name": apk_name,
            "version_code": latest.get("versionCode", ""),
            "version_name": latest.get("versionName", ""),
            "sha256": expected_hash.lower(),
            "download_url": APK_BASE_URL + apk_name
        })

    print(f"Found {len(candidates)} APK candidates.")

    if not candidates:
        raise RuntimeError(
            "Không tìm thấy APK hợp lệ trong F-Droid index."
        )

    return candidates



def download_one(item):
    filename = item["sha256"] + ".apk"
    output_path = OUTPUT_DIR / filename

    # Bỏ qua APK đã tồn tại và đúng SHA256
    if output_path.exists():
        if sha256_file(output_path) == item["sha256"]:
            return {**item, "status": "already_exists"}

        output_path.unlink()

    temp_path = output_path.with_suffix(".apk.part")

    try:
        response = requests.get(
            item["download_url"],
            stream=True,
            timeout=(20, 120)
        )
        response.raise_for_status()

        with open(temp_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if chunk:
                    f.write(chunk)

        actual_hash = sha256_file(temp_path)

        if actual_hash != item["sha256"]:
            temp_path.unlink(missing_ok=True)
            return {
                **item,
                "status": "hash_mismatch"
            }

        temp_path.replace(output_path)

        return {
            **item,
            "status": "downloaded"
        }

    except Exception as e:
        temp_path.unlink(missing_ok=True)

        return {
            **item,
            "status": "failed",
            "error": str(e)
        }


def save_metadata(results):
    fields = [
        "package_name",
        "apk_name",
        "version_code",
        "version_name",
        "sha256",
        "download_url",
        "status",
        "error"
    ]

    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for item in results:
            writer.writerow({
                key: item.get(key, "")
                for key in fields
            })


def main():
    candidates = load_index()

    # Chỉ lấy các APK chưa có trong thư mục
    available = []

    for item in candidates:
        path = OUTPUT_DIR / f'{item["sha256"]}.apk'

        if path.exists() and sha256_file(path) == item["sha256"]:
            continue

        available.append(item)

    random.Random(RANDOM_SEED + int(time.time())).shuffle(available)

    # Lấy một nhóm ứng viên; nếu có lỗi, chạy lại script để bổ sung
    selected = available[:TARGET_COUNT]

    print(f"\n[2/3] Downloading up to {len(selected)} APKs...")
    print(f"Output: {OUTPUT_DIR}")

    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(download_one, item)
            for item in selected
        ]

        for future in tqdm(as_completed(futures), total=len(futures)):
            result = future.result()
            results.append(result)

    save_metadata(results)

    downloaded = sum(
        r["status"] in ("downloaded", "already_exists")
        for r in results
    )

    failed = len(results) - downloaded

    print("\n[3/3] Finished!")
    print(f"Successful APKs in this run: {downloaded}")
    print(f"Failed APKs: {failed}")
    print(f"Metadata: {CSV_PATH}")

    total_valid = sum(
        1 for p in OUTPUT_DIR.glob("*.apk")
    )

    print(f"Total APK files in folder: {total_valid}")

    if total_valid < TARGET_COUNT:
        print(
            f"\nYou still need {TARGET_COUNT - total_valid} APKs. "
            "Run this script again to collect more."
        )


if __name__ == "__main__":
    main()
