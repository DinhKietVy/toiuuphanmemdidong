
import sys
import numpy as np
import pandas as pd
import sklearn
import tensorflow as tf

from androguard.core.apk import APK

print("=" * 50)
print("MOBITIVE ENVIRONMENT CHECK")
print("=" * 50)

print("Python:", sys.version)
print("NumPy:", np.__version__)
print("Pandas:", pd.__version__)
print("Scikit-learn:", sklearn.__version__)
print("TensorFlow:", tf.__version__)
print("Androguard: OK")
print("TensorFlow Lite:", hasattr(tf, "lite"))

print("-" * 50)
print("BUILDING GRU MODEL")

# Input:
# Batch size: 1
# Time steps: 1
# Features: 2915

model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(1, 2915)),

    tf.keras.layers.GRU(
        128,
        unroll=True
    ),

    tf.keras.layers.Dropout(0.5),

    tf.keras.layers.Dense(
        2,
        activation="softmax"
    )
])

model.summary()

print("-" * 50)
print("TESTING TFLITE CONVERSION")

try:
    converter = tf.lite.TFLiteConverter.from_keras_model(model)

    # Chuyển đổi bằng các toán tử TFLite built-in.
    # unroll=True giúp tránh vòng lặp TensorList động
    # trong GRU với sequence length = 1.
    tflite_model = converter.convert()

    print("TFLite conversion: OK")
    print("TFLite model size:", len(tflite_model), "bytes")

    # Kiểm tra model sau khi chuyển đổi
    interpreter = tf.lite.Interpreter(
        model_content=tflite_model
    )

    interpreter.allocate_tensors()

    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    print("Input shape:", input_details[0]["shape"])
    print("Output shape:", output_details[0]["shape"])

    # Thử inference với dữ liệu giả
    sample = np.random.random(
        (1, 1, 2915)
    ).astype(np.float32)

    interpreter.set_tensor(
        input_details[0]["index"],
        sample
    )

    interpreter.invoke()

    prediction = interpreter.get_tensor(
        output_details[0]["index"]
    )

    print("Test prediction:", prediction)
    print("TFLite inference: OK")

    print("=" * 50)
    print("ENVIRONMENT READY")
    print("=" * 50)

except Exception as error:
    print("=" * 50)
    print("TFLITE CONVERSION FAILED")
    print("Error:", error)
    print("=" * 50)

    raise
