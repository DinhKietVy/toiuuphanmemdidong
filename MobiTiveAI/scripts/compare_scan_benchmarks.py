"""
So sánh scan benchmark CSV (xuất từ nút "XUẤT SCAN BENCHMARK CSV") giữa các phiên bản.

Usage:
    python scripts/compare_scan_benchmarks.py \
        --run M34=../MobiTive/mobitive_m34_full.csv \
        --run M5=../MobiTive/mobitive_m5_full.csv \
        [--mode FORCED] [--sha 017ad5f1...] [--since-epoch 1794422850015]

Mặc định chỉ lấy các dòng status=OK, cache_mode=FORCED (quét đầy đủ).
In median / p95 / min-max từng giai đoạn và tốc độ tăng so với run đầu tiên.
Ghi kết quả: reports/scan_benchmark_comparison.csv
"""

import argparse
import csv
import statistics
import sys
from pathlib import Path

# Console Windows (cp1252) không in được tiếng Việt.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parents[1]
OUTPUT = ROOT_DIR / "reports" / "scan_benchmark_comparison.csv"

METRICS = [
    ("total_wall_ms", "Tổng (wall)"),
    ("copy_apk_wall_ms", "Copy APK"),
    ("hash_apk_wall_ms", "SHA-256"),
    ("manifest_wall_ms", "Manifest"),
    ("dex_wall_ms", "DEX (wall)"),
    ("dex_thread_cpu_ms", "DEX (CPU)"),
    ("inference_wall_ms", "Inference"),
    ("pss_after_analysis_kb", "PSS sau phân tích (KB)"),
]


def percentile(values, q):
    values = sorted(values)
    index = max(0, min(len(values) - 1, round(q * (len(values) - 1))))
    return values[index]


def load(path, args):
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        if r.get("status") != "OK":
            continue
        if args.mode != "ALL" and r.get("cache_mode") != args.mode:
            continue
        if args.sha and r.get("apk_sha256") != args.sha:
            continue
        if args.since_epoch and int(r["epoch_ms"]) < args.since_epoch:
            continue
        out.append(r)
    return out


def values(rows, key):
    result = []
    for r in rows:
        v = r.get(key, "")
        if v not in ("", None) and float(v) >= 0:
            result.append(float(v))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="append", required=True,
                        help="NAME=path.csv (lặp lại cho mỗi phiên bản)")
    parser.add_argument("--mode", default="FORCED", help="FORCED | MISS | HIT | ALL")
    parser.add_argument("--sha", default="", help="Chỉ lấy APK có SHA-256 này")
    parser.add_argument("--since-epoch", type=int, default=0)
    args = parser.parse_args()

    runs = []
    for item in args.run:
        name, path = item.split("=", 1)
        rows = load(path, args)
        devices = sorted({r.get("device", "") for r in rows})
        apks = sorted({r.get("apk_name", "") for r in rows})
        print(f"{name}: {len(rows)} dòng | device={devices} | apk={apks}")
        runs.append((name, rows))

    base_name, base_rows = runs[0]
    table = []
    print()
    header = f"{'Giai đoạn':24s}" + "".join(f"{n + ' median':>16s}" for n, _ in runs)
    print(header + f"{'speed-up':>12s}")
    for key, label in METRICS:
        line = f"{label:24s}"
        medians = []
        for name, rows in runs:
            v = values(rows, key)
            med = statistics.median(v) if v else None
            medians.append(med)
            line += f"{(f'{med:,.1f}' if med is not None else '-'):>16s}"
            if v:
                table.append({
                    "run": name, "metric": key, "n": len(v),
                    "median": round(med, 3),
                    "p95": round(percentile(v, 0.95), 3),
                    "min": round(min(v), 3), "max": round(max(v), 3),
                })
        if (medians[0] and medians[-1] and len(runs) > 1
                and not key.startswith("pss")):
            line += f"{medians[0] / medians[-1]:>11.1f}x"
        print(line)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["run", "metric", "n", "median", "p95", "min", "max"])
        writer.writeheader()
        writer.writerows(table)
    print(f"\nSaved: {OUTPUT}")


if __name__ == "__main__":
    main()
