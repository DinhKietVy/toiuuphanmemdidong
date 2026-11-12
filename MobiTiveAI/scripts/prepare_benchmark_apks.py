"""
Chọn và tải bộ APK benchmark theo nhóm dung lượng, giống thiết kế của paper
MobiTive (Sec. IV-B.1: 5, 10, 20, 30, 40, 50 MB).

- Chỉ dùng APK BENIGN từ F-Droid (data/raw/benign/metadata.csv), không cần
  malware để đo tốc độ.
- Dung lượng lấy từ reports/extraction_summary.csv (đã đo lúc trích xuất).
- Mỗi file tải về được kiểm tra SHA-256 với metadata; sai thì bỏ, lấy ứng viên khác.
- Chọn ngẫu nhiên có seed để nhóm khác tái lập được đúng bộ APK.

Usage:
    python scripts/prepare_benchmark_apks.py [--per-bucket 3] [--seed 7]
Kết quả: data/bench_apks/*.apk và data/bench_apks/bench_apks.csv (commit file csv).
"""

import argparse
import csv
import hashlib
import random
import sys
import urllib.request
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parents[1]
METADATA = ROOT_DIR / "data" / "raw" / "benign" / "metadata.csv"
SIZES = ROOT_DIR / "reports" / "extraction_summary.csv"
OUT_DIR = ROOT_DIR / "data" / "bench_apks"

BUCKETS_MB = [5, 10, 20, 30, 40, 50]
TOLERANCE = 0.20  # ±20%


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dst):
    req = urllib.request.Request(url, headers={"User-Agent": "mobitive-benchmark"})
    tmp = dst.with_suffix(".part")
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dst)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-bucket", type=int, default=3)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    with open(SIZES, encoding="utf-8-sig") as f:
        size_of = {r["sha256"]: int(r["file_size"])
                   for r in csv.DictReader(f) if r["label"] == "benign"}
    with open(METADATA, encoding="utf-8-sig") as f:
        candidates = [r for r in csv.DictReader(f)
                      if r["status"] == "downloaded" and r["sha256"] in size_of]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    chosen = []

    for bucket in BUCKETS_MB:
        lo, hi = bucket * (1 - TOLERANCE) * 1e6, bucket * (1 + TOLERANCE) * 1e6
        pool = sorted((r for r in candidates if lo <= size_of[r["sha256"]] <= hi),
                      key=lambda r: r["sha256"])
        rng.shuffle(pool)
        picked = 0
        for r in pool:
            if picked >= args.per_bucket:
                break
            dst = OUT_DIR / f"{bucket:02d}MB_{r['apk_name']}"
            try:
                if not dst.exists() or sha256_of(dst) != r["sha256"]:
                    print(f"[{bucket}MB] tải {r['apk_name']} ...")
                    download(r["download_url"], dst)
                if sha256_of(dst) != r["sha256"]:
                    print(f"  SHA-256 không khớp, bỏ: {r['apk_name']}")
                    dst.unlink(missing_ok=True)
                    continue
            except Exception as e:  # mạng lỗi / F-Droid đã xoá bản cũ
                print(f"  lỗi {r['apk_name']}: {e}")
                dst.unlink(missing_ok=True)
                continue
            picked += 1
            chosen.append({
                "bucket_mb": bucket,
                "file": dst.name,
                "package_name": r["package_name"],
                "bytes": dst.stat().st_size,
                "sha256": r["sha256"],
                "download_url": r["download_url"],
            })
            print(f"  OK {dst.name} ({dst.stat().st_size / 1e6:.1f} MB)")
        if picked < args.per_bucket:
            print(f"[{bucket}MB] CẢNH BÁO: chỉ có {picked}/{args.per_bucket} APK")

    # Xoá APK cũ không còn trong danh sách (đổi seed/per-bucket).
    keep = {c["file"] for c in chosen}
    for stale in OUT_DIR.glob("*.apk"):
        if stale.name not in keep:
            stale.unlink()

    manifest = OUT_DIR / "bench_apks.csv"
    with open(manifest, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(chosen[0].keys()))
        writer.writeheader()
        writer.writerows(chosen)

    total = sum(c["bytes"] for c in chosen) / 1e6
    print(f"\n{len(chosen)} APK, tổng {total:.0f} MB -> {OUT_DIR}")
    print(f"Danh sách: {manifest}")


if __name__ == "__main__":
    main()
