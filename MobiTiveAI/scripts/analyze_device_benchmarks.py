"""
M7 — gộp kết quả đo trên nhiều thiết bị (MobiTive/device_results/**) thành
bảng + biểu đồ cho báo cáo.

Đầu vào (do tools/run_device_benchmark.py kéo về):
    device_results/<máy>/<runId>/scan_*.csv, model_*.csv, device_*.json
Đầu ra:
    reports/device_info.csv               bảng cấu hình máy (như Table I của paper)
    reports/device_scan_summary.csv       máy × model × chế độ × nhóm dung lượng: n, median, p25, p75
    reports/device_model_summary.csv      máy × model × số luồng: p50 / p95 inference
    reports/figures/device_total_vs_size.png
    reports/figures/device_stage_breakdown.png
    reports/figures/device_threads.png
    reports/device_accel_summary.csv      (M8) máy × model × quantization × backend:
                                          p50/p95, init, accuracy/F1 trên máy, speed-up so với CPU-1 FP32
    reports/figures/accel_<máy>.png       (M8) p50 theo backend, nhóm theo quantization

Chỉ tính các dòng status=OK, source=harness, iteration >= 0 (bỏ warm-up).
Usage:
    python scripts/analyze_device_benchmarks.py [--results ../MobiTive/device_results]
"""

import argparse
import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT_DIR.parent / "MobiTive" / "device_results"
REPORTS = ROOT_DIR / "reports"
FIGURES = REPORTS / "figures"

BUCKETS_MB = [5, 10, 20, 30, 40, 50]
STAGES = [  # (csv column, nhãn)
    ("copy_apk_wall_ms", "Copy + SHA-256"),
    ("manifest_wall_ms", "Manifest"),
    ("dex_wall_ms", "DEX"),
    ("inference_wall_ms", "Inference"),
]
METRICS = ["total_wall_ms", "copy_apk_wall_ms", "manifest_wall_ms", "dex_wall_ms",
           "dex_thread_cpu_ms", "inference_wall_ms", "cache_read_wall_ms",
           "gc_time_ms", "blocking_gc_time_ms", "pss_after_analysis_kb"]

# Reference categorical palette (dataviz skill, light mode), fixed order.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
TEXT_PRIMARY, TEXT_SECONDARY, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"


def q(values, p):
    s = sorted(values)
    if not s:
        return None
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def bucket_of(apk_name, nbytes):
    """Nhóm do prepare_benchmark_apks.py đặt trong tên file ("40MB_..."), nếu không có thì lấy nhóm gần nhất."""
    m = re.match(r"(\d+)MB_", apk_name or "")
    if m and int(m.group(1)) in BUCKETS_MB:
        return int(m.group(1))
    mb = nbytes / 1e6
    return min(BUCKETS_MB, key=lambda b: abs(b - mb))


def num(row, key):
    v = row.get(key, "")
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if x >= 0 else None


def load(results_dir):
    scans, models, devices = [], [], []
    for path in sorted(results_dir.rglob("device_*.json")):
        info = json.loads(path.read_text(encoding="utf-8"))
        info["run_dir"] = str(path.parent.relative_to(results_dir))
        devices.append(info)
    for path in sorted(results_dir.rglob("scan_*.csv")):
        with open(path, encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                if r.get("status") != "OK" or r.get("source") != "harness":
                    continue
                if int(r.get("iteration") or -1) < 0:
                    continue
                r["device_label"] = f"{r['device']}"
                r["bucket_mb"] = bucket_of(r.get("apk_name"), int(r["apk_bytes"]))
                scans.append(r)
    for path in sorted(results_dir.rglob("model_*.csv")):
        with open(path, encoding="utf-8-sig") as f:
            models.extend(r for r in csv.DictReader(f) if r.get("status") == "OK")
    accel = []
    for path in sorted(results_dir.rglob("accel_*.csv")):
        with open(path, encoding="utf-8-sig") as f:
            accel.extend(csv.DictReader(f))
    return scans, models, devices, accel


def write_csv(path, rows):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Saved: {path}")


def summarize_scans(scans):
    groups = defaultdict(list)
    for r in scans:
        groups[(r["device_label"], r["model_id"], r["cache_mode"], r["bucket_mb"])].append(r)
    out = []
    for (dev, model, mode, bucket), rows in sorted(groups.items()):
        rec = {"device": dev, "model_id": model, "cache_mode": mode, "bucket_mb": bucket,
               "n": len(rows), "apks": len({r["apk_sha256"] for r in rows}),
               "max_thermal_status": max(int(r.get("thermal_status") or -1) for r in rows)}
        for m in METRICS:
            v = [x for x in (num(r, m) for r in rows) if x is not None]
            rec[f"{m}_median"] = round(q(v, .5), 2) if v else ""
            rec[f"{m}_p25"] = round(q(v, .25), 2) if v else ""
            rec[f"{m}_p75"] = round(q(v, .75), 2) if v else ""
        out.append(rec)
    return out


def summarize_models(models):
    groups = defaultdict(list)
    for r in models:
        groups[(r["device"], r["model_id"], int(r["threads"]))].append(r)
    out = []
    for (dev, model, threads), rows in sorted(groups.items()):
        p50 = [float(r["inference_p50_ms"]) for r in rows]
        p95 = [float(r["inference_p95_ms"]) for r in rows]
        out.append({"device": dev, "model_id": model, "threads": threads, "runs": len(rows),
                    "model_bytes": rows[0]["model_bytes"],
                    "inference_p50_ms": round(statistics.median(p50), 4),
                    "inference_p95_ms": round(statistics.median(p95), 4),
                    "same_label_as_baseline": all(r["same_label_as_baseline"] != "false" for r in rows)})
    return out


def print_overview(summary):
    print("\nFORCED, median tổng thời gian quét (ms) theo nhóm dung lượng")
    devices = sorted({r["device"] for r in summary})
    print(f"{'Thiết bị':32s}" + "".join(f"{b:>9d}MB" for b in BUCKETS_MB))
    for dev in devices:
        cells = {r["bucket_mb"]: r["total_wall_ms_median"] for r in summary
                 if r["device"] == dev and r["cache_mode"] == "FORCED" and r["model_id"] == "gru128_fp32"}
        print(f"{dev[:32]:32s}" + "".join(
            f"{(f'{cells[b]:,.0f}' if cells.get(b) not in (None, '') else '-'):>11s}" for b in BUCKETS_MB))


# ------------------------------------------------------------------ figures

def style_axes(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=TEXT_SECONDARY, labelsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def plot(summary, model_summary):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(Bỏ qua biểu đồ: chưa cài matplotlib — pip install matplotlib)")
        return
    FIGURES.mkdir(parents=True, exist_ok=True)
    forced = [r for r in summary if r["cache_mode"] == "FORCED" and r["model_id"] == "gru128_fp32"]
    devices = sorted({r["device"] for r in forced})
    if len(devices) > len(SERIES):
        print(f"Cảnh báo: {len(devices)} thiết bị > {len(SERIES)} màu; chỉ vẽ {len(SERIES)} máy đầu.")
        devices = devices[:len(SERIES)]

    # 1) Total scan time vs APK size, one line per device (single y axis, ms).
    fig, ax = plt.subplots(figsize=(7.5, 4.2), facecolor=SURFACE)
    style_axes(ax)
    for i, dev in enumerate(devices):
        pts = sorted((r["bucket_mb"], r["total_wall_ms_median"], r["total_wall_ms_p25"],
                      r["total_wall_ms_p75"]) for r in forced if r["device"] == dev)
        if not pts:
            continue
        x = [p[0] for p in pts]
        y = [p[1] for p in pts]
        ax.fill_between(x, [p[2] for p in pts], [p[3] for p in pts], color=SERIES[i], alpha=0.12, linewidth=0)
        ax.plot(x, y, color=SERIES[i], linewidth=2, marker="o", markersize=6,
                markeredgecolor=SURFACE, markeredgewidth=2, label=dev)
        ax.annotate(dev, (x[-1], y[-1]), xytext=(6, 0), textcoords="offset points",
                    va="center", fontsize=8, color=TEXT_PRIMARY)
    ax.set_xlabel("Dung lượng APK (MB)", color=TEXT_SECONDARY)
    ax.set_ylabel("Tổng thời gian quét, median (ms)", color=TEXT_SECONDARY)
    ax.set_xticks(BUCKETS_MB)
    ax.set_ylim(bottom=0)
    ax.set_title("Thời gian quét đầy đủ (FORCED) theo dung lượng APK — vùng mờ: IQR",
                 color=TEXT_PRIMARY, fontsize=11, loc="left")
    if len(devices) >= 2:
        ax.legend(frameon=False, fontsize=8, labelcolor=TEXT_PRIMARY)
    fig.tight_layout()
    fig.savefig(FIGURES / "device_total_vs_size.png", dpi=200)
    plt.close(fig)

    # 2) Stage breakdown per device (stacked horizontal bars, median over all FORCED runs).
    fig, ax = plt.subplots(figsize=(7.5, 0.6 * max(2, len(devices)) + 1.6), facecolor=SURFACE)
    style_axes(ax)
    ax.yaxis.grid(False)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    for row, dev in enumerate(devices):
        left = 0.0
        for j, (col, label) in enumerate(STAGES):
            vals = [r[f"{col}_median"] for r in forced if r["device"] == dev and r[f"{col}_median"] != ""]
            width = statistics.median(vals) if vals else 0
            ax.barh(row, width, left=left, color=SERIES[j], height=0.55,
                    edgecolor=SURFACE, linewidth=2, label=label if row == 0 else None)
            left += width
        ax.text(left, row, f"  {left:,.0f} ms", va="center", fontsize=8, color=TEXT_PRIMARY)
    ax.set_yticks(range(len(devices)))
    ax.set_yticklabels(devices, color=TEXT_PRIMARY)
    ax.invert_yaxis()
    ax.set_xlabel("Thời gian, median trên mọi APK (ms)", color=TEXT_SECONDARY)
    ax.set_title("Phân rã thời gian quét theo giai đoạn", color=TEXT_PRIMARY, fontsize=11, loc="left")
    ax.legend(frameon=False, fontsize=8, ncol=len(STAGES), loc="upper left",
              bbox_to_anchor=(0, -0.25 if len(devices) < 3 else -0.12), labelcolor=TEXT_PRIMARY)
    fig.tight_layout()
    fig.savefig(FIGURES / "device_stage_breakdown.png", dpi=200)
    plt.close(fig)

    # 3) Inference p50 vs thread count, small multiples per model (paper 2, Table VII).
    models = sorted({r["model_id"] for r in model_summary})
    if models:
        fig, axes = plt.subplots(1, len(models), figsize=(2.4 * len(models), 3.0),
                                 facecolor=SURFACE, sharey=True, squeeze=False)
        for k, model in enumerate(models):
            ax = axes[0][k]
            style_axes(ax)
            for i, dev in enumerate(devices):
                pts = sorted((r["threads"], r["inference_p50_ms"]) for r in model_summary
                             if r["device"] == dev and r["model_id"] == model)
                if pts:
                    ax.plot([p[0] for p in pts], [p[1] for p in pts], color=SERIES[i], linewidth=2,
                            marker="o", markersize=6, markeredgecolor=SURFACE, markeredgewidth=2,
                            label=dev)
            ax.set_xticks([1, 2, 4])
            ax.set_title(model.replace("mobitive_", ""), fontsize=9, color=TEXT_PRIMARY)
            ax.set_xlabel("Số luồng CPU", color=TEXT_SECONDARY, fontsize=8)
            ax.set_ylim(bottom=0)
        axes[0][0].set_ylabel("Inference p50 (ms)", color=TEXT_SECONDARY)
        if len(devices) >= 2:
            axes[0][-1].legend(frameon=False, fontsize=7, labelcolor=TEXT_PRIMARY)
        fig.suptitle("TFLite inference theo số luồng", x=0.01, ha="left",
                     color=TEXT_PRIMARY, fontsize=11)
        fig.tight_layout()
        fig.savefig(FIGURES / "device_threads.png", dpi=200)
        plt.close(fig)
    print(f"Saved figures: {FIGURES}")


# ------------------------------------------------------------------ M8 accel

BACKENDS = ["cpu1", "cpu2", "cpu4", "cpu1_noxnnpack", "gpu_fp32", "gpu_fp16", "nnapi"]
QUANTS = ["fp32", "fp16", "dynamic", "int8"]


def summarize_accel(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["device"], r["variant"], r["backend"])].append(r)
    base = {}  # (device, arch) -> p50 of cpu1 fp32, the paper-2 baseline
    for (dev, variant, backend), rs in groups.items():
        ok = [r for r in rs if r["status"] == "OK"]
        if ok and backend == "cpu1" and ok[0]["quant"] == "fp32":
            base[(dev, ok[0]["arch"])] = statistics.median(float(r["p50_ms"]) for r in ok)
    out = []
    for (dev, variant, backend), rs in sorted(groups.items()):
        ok = [r for r in rs if r["status"] == "OK"]
        first = rs[0]
        rec = {"device": dev, "variant": variant, "arch": first["arch"], "quant": first["quant"],
               "backend": backend, "runs": len(rs), "status": "OK" if ok else first["status"],
               "error": "" if ok else first.get("error", "")}
        if ok:
            med = lambda k: statistics.median(float(r[k]) for r in ok if r.get(k) not in ("", None))
            p50 = med("p50_ms")
            b = base.get((dev, first["arch"]))
            rec.update({"model_bytes": first["model_bytes"], "init_ms": round(med("init_ms"), 2),
                        "p50_ms": round(p50, 4), "p95_ms": round(med("p95_ms"), 4),
                        "speedup_vs_cpu1_fp32": round(b / p50, 2) if b and p50 else "",
                        "accuracy": round(med("accuracy"), 4), "f1": round(med("f1"), 4),
                        "fn": ok[0]["fn"], "fp": ok[0]["fp"],
                        "agreement_with_desktop": ok[0]["agreement_with_desktop"],
                        "max_prob_delta_vs_desktop": ok[0]["max_prob_delta_vs_desktop"],
                        "max_thermal_status": max(int(r["thermal_status"] or -1) for r in ok)})
        out.append(rec)
    return out


def print_accel(summary):
    for dev in sorted({r["device"] for r in summary}):
        print(f"\n[{dev}] inference p50 (ms) — hàng: model, cột: backend  (x = lỗi/không hỗ trợ)")
        print(f"{'':22s}" + "".join(f"{b:>15s}" for b in BACKENDS))
        for variant in sorted({r["variant"] for r in summary if r["device"] == dev}):
            cells = {r["backend"]: r for r in summary if r["device"] == dev and r["variant"] == variant}
            line = f"{variant.replace('mobitive_', ''):22s}"
            for b in BACKENDS:
                r = cells.get(b)
                if r is None:
                    cell = "-"
                elif r["status"] == "OK":
                    cell = f"{r['p50_ms']:.3f}"
                else:
                    cell = "x"
                line += f"{cell:>15s}"
            print(line)
        bad = [r for r in summary if r["device"] == dev and r["status"] == "OK"
               and r["agreement_with_desktop"] not in ("", None) and float(r["agreement_with_desktop"]) < 1]
        accs = sorted({r["accuracy"] for r in summary if r["device"] == dev and r["status"] == "OK"})
        print(f"  accuracy trên máy: {accs}")
        for r in bad:
            print(f"  LỆCH so với desktop: {r['variant']} {r['backend']} agreement={r['agreement_with_desktop']}")


def plot_accel(summary):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    FIGURES.mkdir(parents=True, exist_ok=True)
    for dev in sorted({r["device"] for r in summary}):
        rows = [r for r in summary if r["device"] == dev and r["status"] == "OK"]
        archs = [a for a in ("gru128", "gru64", "mlp64") if any(r["arch"] == a for r in rows)]
        backends = [b for b in BACKENDS if any(r["backend"] == b for r in rows)]
        if not archs or not backends:
            continue
        fig, axes = plt.subplots(len(archs), 1, figsize=(8, 2.6 * len(archs)), facecolor=SURFACE,
                                 squeeze=False)
        width = 0.8 / len(QUANTS)
        for k, arch in enumerate(archs):
            ax = axes[k][0]
            style_axes(ax)
            for j, quant in enumerate(QUANTS):
                xs, ys = [], []
                for i, b in enumerate(backends):
                    hit = [r for r in rows if r["arch"] == arch and r["quant"] == quant and r["backend"] == b]
                    if hit:
                        xs.append(i - 0.4 + width * (j + 0.5))
                        ys.append(hit[0]["p50_ms"])
                ax.bar(xs, ys, width=width, color=SERIES[j], edgecolor=SURFACE, linewidth=2,
                       label=quant.upper() if k == 0 else None)
            # Mark backend slots where this architecture failed / was unsupported,
            # so an empty slot is never read as "0 ms".
            for i, b in enumerate(backends):
                if not any(r["arch"] == arch and r["backend"] == b for r in rows):
                    ax.text(i, 0, "không chạy\nđược", ha="center", va="bottom",
                            fontsize=7, color=TEXT_SECONDARY)
            ax.set_xticks(range(len(backends)))
            ax.set_xticklabels(backends if k == len(archs) - 1 else [""] * len(backends),
                               color=TEXT_PRIMARY, fontsize=8)
            ax.set_ylabel(f"{arch}\np50 (ms)", color=TEXT_SECONDARY, fontsize=9)
            ax.set_ylim(bottom=0)
        axes[0][0].legend(frameon=False, ncol=len(QUANTS), fontsize=8, loc="upper left",
                          labelcolor=TEXT_PRIMARY)
        fig.suptitle(f"Inference p50 theo backend và quantization — {dev}", x=0.01, ha="left",
                     color=TEXT_PRIMARY, fontsize=11)
        fig.tight_layout()
        name = re.sub(r"[^A-Za-z0-9]+", "_", dev)
        fig.savefig(FIGURES / f"accel_{name}.png", dpi=200)
        plt.close(fig)
    print(f"Saved accel figures: {FIGURES}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()
    if not args.results.exists():
        sys.exit(f"Không thấy {args.results}. Chạy MobiTive/tools/run_device_benchmark.py trước.")

    scans, models, devices, accel = load(args.results)
    print(f"{len(devices)} lần chạy, {len(scans)} dòng scan hợp lệ, {len(models)} dòng model, "
          f"{len(accel)} dòng accel.")
    if accel:
        accel_summary = summarize_accel(accel)
        write_csv(REPORTS / "device_accel_summary.csv", accel_summary)
        print_accel(accel_summary)
        plot_accel(accel_summary)
    if not scans:
        sys.exit("Không có dữ liệu scan hợp lệ." if not accel else 0)

    write_csv(REPORTS / "device_info.csv", [
        {k: (",".join(map(str, v)) if isinstance(v, list) else v) for k, v in d.items()} for d in devices])
    summary = summarize_scans(scans)
    write_csv(REPORTS / "device_scan_summary.csv", summary)
    model_summary = summarize_models(models)
    write_csv(REPORTS / "device_model_summary.csv", model_summary)
    print_overview(summary)
    plot(summary, model_summary)


if __name__ == "__main__":
    main()
