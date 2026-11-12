"""
So sánh extractor M5 (DEX method_ids) với extractor cũ (Androguard duyệt invoke-*).

Dùng để chứng minh trong báo cáo:
  1. Parity: vector 2290 API features (theo feature_dictionary.json) gần như trùng
     -> model đã train vẫn dùng được, train/serve nhất quán.
  2. Tốc độ: thời gian trích xuất DEX của 2 cách.

Usage:
    python scripts/compare_dex_extractors.py path/to/a.apk path/to/dir_with_apks ...
    python scripts/compare_dex_extractors.py --no-legacy ...   # chỉ đo M5
Kết quả: reports/m5_dex_parity.csv
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "src"))

from mobitive.dex_extractor import (  # noqa: E402
    extract_api_calls,
    extract_api_calls_legacy,
)

DICTIONARY = ROOT_DIR / "artifacts" / "metadata" / "feature_dictionary.json"
OUTPUT = ROOT_DIR / "reports" / "m5_dex_parity.csv"


def collect_apks(paths):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            yield from sorted(p.rglob("*.apk"))
        elif p.suffix.lower() == ".apk":
            yield p


def jaccard(a, b):
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--no-legacy", action="store_true")
    args = parser.parse_args()

    with open(DICTIONARY, encoding="utf-8") as f:
        dict_api = set(json.load(f)["api_features"])

    rows = []
    for apk in collect_apks(args.paths):
        t0 = time.perf_counter()
        new = extract_api_calls(apk)
        new_ms = (time.perf_counter() - t0) * 1000
        new_set = set(new["api_calls"])

        row = {
            "apk": apk.name,
            "apk_bytes": apk.stat().st_size,
            "dex_files": new["dex_file_count"],
            "method_refs": new["method_ref_count"],
            "m5_ms": round(new_ms, 1),
            "m5_unique_api": len(new_set),
            "m5_dict_active": len(new_set & dict_api),
        }

        if not args.no_legacy:
            from androguard.misc import AnalyzeAPK
            from loguru import logger
            logger.remove()

            t0 = time.perf_counter()
            _, dex_list, _ = AnalyzeAPK(str(apk))
            load_ms = (time.perf_counter() - t0) * 1000
            t0 = time.perf_counter()
            old = extract_api_calls_legacy(dex_list)
            walk_ms = (time.perf_counter() - t0) * 1000
            old_set = set(old["api_calls"])
            old_dict, new_dict = old_set & dict_api, new_set & dict_api

            row.update({
                "legacy_load_ms": round(load_ms, 1),
                "legacy_walk_ms": round(walk_ms, 1),
                "legacy_unique_api": len(old_set),
                "legacy_dict_active": len(old_dict),
                "all_api_jaccard": round(jaccard(old_set, new_set), 5),
                "only_legacy": len(old_set - new_set),
                "only_m5": len(new_set - old_set),
                "dict_vector_hamming": len(old_dict ^ new_dict),
                "dict_jaccard": round(jaccard(old_dict, new_dict), 5),
                "sample_only_legacy": " | ".join(sorted(old_set - new_set)[:3]),
                "sample_only_m5": " | ".join(sorted(new_set - old_set)[:3]),
            })

        rows.append(row)
        print(json.dumps(row, ensure_ascii=False))

    if not rows:
        print("Không có APK nào.")
        return

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved: {OUTPUT}")


if __name__ == "__main__":
    main()
