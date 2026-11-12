"""
M8 — xuất đầy đủ các biến thể TFLite (paper 2: quantization × phần cứng) và
đánh giá chúng trên desktop. Thay cho các bước xuất fp16/dynamic/... trước đây
không có script (khó tái lập).

Kiến trúc:  gru128 (mobitive_gru_best.keras), gru64, mlp64
Quantization:
    fp32     không tối ưu
    fp16     trọng số float16 (giải nén về float32 khi chạy CPU; GPU dùng trực tiếp)
    dynamic  dynamic-range: trọng số int8, activation float (paper 2: "DYN")
    int8     full-integer với representative dataset từ X_train (paper 2: "INT8");
             vào/ra vẫn float32 để app không phải đổi code. Nếu có op không
             lượng tử hoá được thì cho phép op float (ghi chú "int8_fallback").

Đầu ra:
    artifacts/models/variants/mobitive_<arch>_<quant>.tflite
    reports/model_variants.csv              size, accuracy, F1, ... trên test set (desktop)
    reports/model_variants_desktop_pred.csv xác suất malware từng mẫu test (để so với điện thoại)
    MobiTive/app/src/androidTest/assets/accel/   model + test_vectors.bin + desktop_pred.csv

Usage:
    python scripts/export_model_variants.py
"""

import csv
import struct
import sys
import time
from pathlib import Path

import numpy as np
import tensorflow as tf

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT_DIR / "artifacts" / "models"
OUT_DIR = MODELS_DIR / "variants"
DATA_DIR = ROOT_DIR / "data" / "processed" / "dataset"
REPORTS = ROOT_DIR / "reports"
ANDROID_ASSETS = ROOT_DIR.parent / "MobiTive" / "app" / "src" / "androidTest" / "assets" / "accel"

ARCHS = {
    "gru128": "mobitive_gru_best.keras",
    "gru64": "mobitive_gru64_best.keras",
    "mlp64": "mobitive_mlp64_best.keras",
}
QUANTS = ["fp32", "fp16", "dynamic", "int8"]


def shape_input(x, model):
    """GRU nhận [N, 1, 2915]; MLP nhận [N, 2915]."""
    return x.reshape((-1, *model.input_shape[1:])).astype(np.float32)


def convert(model, quant, x_rep):
    conv = tf.lite.TFLiteConverter.from_keras_model(model)
    note = ""
    if quant == "fp16":
        conv.optimizations = [tf.lite.Optimize.DEFAULT]
        conv.target_spec.supported_types = [tf.float16]
    elif quant == "dynamic":
        conv.optimizations = [tf.lite.Optimize.DEFAULT]
    elif quant == "int8":
        conv.optimizations = [tf.lite.Optimize.DEFAULT]

        def representative():
            for row in x_rep:
                yield [row[np.newaxis, ...]]

        conv.representative_dataset = representative
        conv.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
        try:
            return conv.convert(), "int8_full"
        except Exception as e:  # e.g. GRU ops without int8 kernels
            print(f"    full INT8 thất bại ({type(e).__name__}); cho phép op float")
            conv.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8,
                                              tf.lite.OpsSet.TFLITE_BUILTINS]
            note = "int8_fallback"
    return conv.convert(), note


def run_tflite(content, x):
    interp = tf.lite.Interpreter(model_content=content, num_threads=1)
    interp.allocate_tensors()
    inp = interp.get_input_details()[0]
    out = interp.get_output_details()[0]
    probs, times = [], []
    for row in x:
        interp.set_tensor(inp["index"], row[np.newaxis, ...])
        t = time.perf_counter()
        interp.invoke()
        times.append((time.perf_counter() - t) * 1000)
        probs.append(interp.get_tensor(out["index"])[0].copy())
    details = interp.get_tensor_details()
    int8 = sum(1 for d in details if d["dtype"] in (np.int8, np.uint8))
    return np.array(probs), float(np.median(times)), int8 / max(1, len(details))


def metrics(y, prob_malware):
    pred = (prob_malware > 0.5).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"accuracy": (tp + tn) / len(y), "precision": precision, "recall": recall,
            "f1": f1, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def write_test_vectors(x, y, path):
    """MTV1 | n u32 | dim u32 | labels n×u8 | n × ceil(dim/8) bit-packed rows (LSB-first)."""
    x01 = (x.reshape(len(x), -1) > 0.5).astype(np.uint8)
    if not np.array_equal(x01.astype(np.float32), x.reshape(len(x), -1)):
        raise ValueError("Test vectors are not binary")
    packed = np.packbits(x01, axis=1, bitorder="little")
    with open(path, "wb") as f:
        f.write(b"MTV1")
        f.write(struct.pack("<II", x01.shape[0], x01.shape[1]))
        f.write(y.astype(np.uint8).tobytes())
        f.write(packed.tobytes())


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ANDROID_ASSETS.joinpath("models").mkdir(parents=True, exist_ok=True)
    x_train = np.load(DATA_DIR / "X_train.npy")
    x_test = np.load(DATA_DIR / "X_test.npy")
    y_test = np.load(DATA_DIR / "y_test.npy").astype(int)

    rows, pred_rows = [], []
    for arch, keras_file in ARCHS.items():
        model = tf.keras.models.load_model(MODELS_DIR / keras_file)
        xt = shape_input(x_test, model)
        xr = shape_input(x_train, model)
        keras_prob = model.predict(xt, verbose=0)[:, 1]
        print(f"\n{arch}: input {model.input_shape}, Keras acc "
              f"{metrics(y_test, keras_prob)['accuracy']:.4f}")

        for quant in QUANTS:
            name = f"mobitive_{arch}_{quant}"
            print(f"  -> {name}")
            content, note = convert(model, quant, xr)
            (OUT_DIR / f"{name}.tflite").write_bytes(content)
            (ANDROID_ASSETS / "models" / f"{name}.tflite").write_bytes(content)

            probs, p50, int8_ratio = run_tflite(content, xt)
            m = metrics(y_test, probs[:, 1])
            rows.append({
                "variant": name, "arch": arch, "quant": quant, "note": note,
                "bytes": len(content),
                **{k: round(v, 5) if isinstance(v, float) else v for k, v in m.items()},
                "agreement_with_keras": round(float(((probs[:, 1] > .5) == (keras_prob > .5)).mean()), 5),
                "max_prob_delta_vs_keras": round(float(np.abs(probs[:, 1] - keras_prob).max()), 6),
                "int8_tensor_ratio": round(int8_ratio, 3),
                "desktop_p50_ms": round(p50, 4),
            })
            for i, p in enumerate(probs[:, 1]):
                pred_rows.append({"variant": name, "index": i, "label": int(y_test[i]),
                                  "p_malware": f"{p:.6f}"})
            print(f"     {len(content) / 1024:8.0f} KB  acc {m['accuracy']:.4f}  F1 {m['f1']:.4f}  "
                  f"int8 tensors {int8_ratio:.0%}  {note}")

    REPORTS.mkdir(parents=True, exist_ok=True)
    for path, data in [(REPORTS / "model_variants.csv", rows),
                       (REPORTS / "model_variants_desktop_pred.csv", pred_rows),
                       (ANDROID_ASSETS / "desktop_pred.csv", pred_rows)]:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
        print(f"Saved: {path}")

    write_test_vectors(x_test, y_test, ANDROID_ASSETS / "test_vectors.bin")
    print(f"Saved: {ANDROID_ASSETS / 'test_vectors.bin'} ({len(x_test)} mẫu)")


if __name__ == "__main__":
    main()
