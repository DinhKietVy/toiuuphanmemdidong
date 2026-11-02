
import json
from pathlib import Path

import numpy as np
import tensorflow as tf


ROOT_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    ROOT_DIR / "artifacts" / "models"
    / "mobitive_gru_best.keras"
)

OUTPUT_DIR = ROOT_DIR / "artifacts" / "models"
DATA_DIR = ROOT_DIR / "data" / "processed" / "dataset"
METADATA_DIR = ROOT_DIR / "artifacts" / "metadata"

TFLITE_PATH = OUTPUT_DIR / "mobitive_gru.tflite"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 65)
    print("MOBITIVE TENSORFLOW LITE EXPORT")
    print("=" * 65)

    # 1. Load Keras model
    print("\n[1/5] Loading Keras model...")

    model = tf.keras.models.load_model(MODEL_PATH)

    print("Model loaded:", MODEL_PATH)
    print("Input shape:", model.input_shape)
    print("Output shape:", model.output_shape)

    # 2. Convert model
    print("\n[2/5] Converting to TensorFlow Lite...")

    converter = tf.lite.TFLiteConverter.from_keras_model(model)

    # Float32 trước tiên để ưu tiên độ chính xác.
    converter.optimizations = []

    # Chỉ sử dụng TensorFlow Lite built-in operators.
    converter.target_spec.supported_ops = [
        tf.lite.OpsSet.TFLITE_BUILTINS
    ]

    tflite_model = converter.convert()

    # 3. Save model
    print("\n[3/5] Saving TFLite model...")

    with open(TFLITE_PATH, "wb") as f:
        f.write(tflite_model)

    print("Saved:", TFLITE_PATH)
    print("Model size:", round(len(tflite_model) / 1024, 2), "KB")

    # 4. Test TFLite interpreter
    print("\n[4/5] Testing TFLite interpreter...")

    interpreter = tf.lite.Interpreter(
        model_path=str(TFLITE_PATH)
    )

    interpreter.allocate_tensors()

    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    print("TFLite input:", input_details[0]["shape"])
    print("TFLite output:", output_details[0]["shape"])

    # 5. Compare Keras and TFLite predictions
    print("\n[5/5] Comparing Keras and TFLite...")

    X_test = np.load(DATA_DIR / "X_test.npy")

    # Kiểm tra 20 mẫu đầu tiên.
    test_samples = X_test[:20].reshape(
        -1, 1, X_test.shape[1]
    ).astype(np.float32)

    max_difference = 0.0
    same_predictions = 0

    for sample in test_samples:
        keras_output = model.predict(
            sample[np.newaxis, ...],
            verbose=0,
        )[0]

        interpreter.set_tensor(
            input_details[0]["index"],
            sample[np.newaxis, ...],
        )

        interpreter.invoke()

        tflite_output = interpreter.get_tensor(
            output_details[0]["index"]
        )[0]

        difference = np.max(
            np.abs(keras_output - tflite_output)
        )

        max_difference = max(
            max_difference,
            float(difference),
        )

        if np.argmax(keras_output) == np.argmax(tflite_output):
            same_predictions += 1

    print("\nCOMPARISON RESULT")
    print("-" * 50)
    print("Test samples:", len(test_samples))
    print("Same predictions:", same_predictions)
    print(
        "Prediction agreement:",
        f"{same_predictions / len(test_samples) * 100:.2f}%"
    )
    print("Maximum absolute difference:", max_difference)

    # Save metadata for Android integration.
    with open(
        METADATA_DIR / "feature_dictionary.json",
        "r",
        encoding="utf-8",
    ) as f:
        dictionary = json.load(f)

    metadata = {
        "model_name": "MobiTive GRU",
        "model_format": "TensorFlow Lite",
        "input_shape": [1, 1, dictionary["total_feature_count"]],
        "input_dtype": "float32",
        "output_shape": [1, 2],
        "output_classes": {
            "0": "Benign",
            "1": "Malware",
        },
        "feature_dictionary": "feature_dictionary.json",
        "representation": "binary_presence",
    }

    metadata_path = METADATA_DIR / "tflite_metadata.json"

    with open(
        metadata_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            metadata,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print("\nMetadata:", metadata_path)

    print("\n" + "=" * 65)
    print("TFLITE EXPORT COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
