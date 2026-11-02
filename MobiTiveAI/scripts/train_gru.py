
import json
import random
from pathlib import Path

import numpy as np
import tensorflow as tf

from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score,
)

from tensorflow.keras import Sequential
from tensorflow.keras.layers import Input, GRU, Dropout, Dense
from tensorflow.keras.callbacks import (
    EarlyStopping,
    ReduceLROnPlateau,
    ModelCheckpoint,
)


# ============================================================
# CONFIG
# ============================================================

ROOT_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = ROOT_DIR / "data" / "processed" / "dataset"
METADATA_DIR = ROOT_DIR / "artifacts" / "metadata"
MODEL_DIR = ROOT_DIR / "artifacts" / "models"
REPORT_DIR = ROOT_DIR / "reports"

RANDOM_STATE = 42

EPOCHS = 100
BATCH_SIZE = 16
LEARNING_RATE = 0.001

GRU_UNITS = 128
DROPOUT_RATE = 0.5

MODEL_PATH = MODEL_DIR / "mobitive_gru_best.keras"


# ============================================================
# REPRODUCIBILITY
# ============================================================

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    tf.keras.utils.set_random_seed(seed)


# ============================================================
# LOAD DATA
# ============================================================

def load_data():
    X_train = np.load(DATA_DIR / "X_train.npy")
    y_train = np.load(DATA_DIR / "y_train.npy")

    X_val = np.load(DATA_DIR / "X_validation.npy")
    y_val = np.load(DATA_DIR / "y_validation.npy")

    X_test = np.load(DATA_DIR / "X_test.npy")
    y_test = np.load(DATA_DIR / "y_test.npy")

    # Kiểm tra kích thước feature dictionary.
    with open(
        METADATA_DIR / "feature_dictionary.json",
        "r",
        encoding="utf-8",
    ) as f:
        dictionary = json.load(f)

    expected_features = dictionary["total_feature_count"]

    for name, X, y in [
        ("train", X_train, y_train),
        ("validation", X_val, y_val),
        ("test", X_test, y_test),
    ]:
        if X.ndim != 2:
            raise ValueError(
                f"{name}: X phải có 2 chiều, nhận được {X.shape}"
            )

        if X.shape[1] != expected_features:
            raise ValueError(
                f"{name}: số feature không khớp dictionary. "
                f"Expected={expected_features}, actual={X.shape[1]}"
            )

        if len(X) != len(y):
            raise ValueError(
                f"{name}: số lượng X và y không khớp."
            )

        if not np.isfinite(X).all():
            raise ValueError(f"{name}: X chứa NaN hoặc Infinity.")

    # GRU nhận tensor 3 chiều:
    # (samples, timesteps, features)
    X_train = X_train.reshape(
        X_train.shape[0], 1, X_train.shape[1]
    )

    X_val = X_val.reshape(
        X_val.shape[0], 1, X_val.shape[1]
    )

    X_test = X_test.reshape(
        X_test.shape[0], 1, X_test.shape[1]
    )

    return (
        X_train, y_train,
        X_val, y_val,
        X_test, y_test,
        expected_features,
    )


# ============================================================
# BUILD GRU MODEL
# ============================================================

def build_model(input_features):
    model = Sequential([
        Input(shape=(1, input_features)),

        GRU(
            GRU_UNITS,
            unroll=True,
            name="gru_layer",
        ),

        Dropout(DROPOUT_RATE),

        Dense(
            2,
            activation="softmax",
            name="classification_output",
        ),
    ])

    optimizer = tf.keras.optimizers.Adam(
        learning_rate=LEARNING_RATE
    )

    model.compile(
        optimizer=optimizer,
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )

    return model


# ============================================================
# TRAIN
# ============================================================

def train_model(
    model,
    X_train,
    y_train,
    X_val,
    y_val,
):
    classes = np.unique(y_train)

    if len(classes) != 2:
        raise ValueError(
            f"Train phải có đủ 2 class, nhận được: {classes}"
        )

    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y_train,
    )

    class_weights = {
        int(label): float(weight)
        for label, weight in zip(classes, weights)
    }

    print("\nCLASS WEIGHTS")
    print("-" * 50)

    for label, weight in class_weights.items():
        name = "Benign" if label == 0 else "Malware"
        print(f"{name}: {weight:.4f}")

    callbacks = [
        ModelCheckpoint(
            filepath=str(MODEL_PATH),
            monitor="val_loss",
            save_best_only=True,
            mode="min",
            verbose=1,
        ),

        EarlyStopping(
            monitor="val_loss",
            patience=15,
            restore_best_weights=True,
            verbose=1,
        ),

        ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=5,
            min_lr=1e-6,
            verbose=1,
        ),
    ]

    history = model.fit(
        X_train,
        y_train,

        validation_data=(X_val, y_val),

        epochs=EPOCHS,
        batch_size=BATCH_SIZE,

        class_weight=class_weights,

        callbacks=callbacks,
        shuffle=True,
        verbose=1,
    )

    return history, class_weights


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(model, X_test, y_test):
    probabilities = model.predict(
        X_test,
        verbose=0,
    )

    predictions = np.argmax(
        probabilities,
        axis=1,
    )

    malware_probabilities = probabilities[:, 1]

    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test,
        predictions,
        pos_label=1,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        pos_label=1,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        pos_label=1,
        zero_division=0,
    )

    cm = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    )

    # ROC-AUC và PR-AUC không xác định nếu test chỉ có một class.
    if len(np.unique(y_test)) == 2:
        roc_auc = roc_auc_score(
            y_test,
            malware_probabilities,
        )

        pr_auc = average_precision_score(
            y_test,
            malware_probabilities,
        )
    else:
        roc_auc = None
        pr_auc = None

    print("\n" + "=" * 65)
    print("TEST SET EVALUATION")
    print("=" * 65)

    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc}")
    print(f"PR-AUC:    {pr_auc}")

    print("\nCONFUSION MATRIX")
    print("Rows = Actual, Columns = Predicted")
    print("                 Pred Benign   Pred Malware")
    print(f"Actual Benign        {cm[0][0]:5d}          {cm[0][1]:5d}")
    print(f"Actual Malware       {cm[1][0]:5d}          {cm[1][1]:5d}")

    print("\nCLASSIFICATION REPORT")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Benign", "Malware"],
            zero_division=0,
        )
    )

    results = {
        "accuracy": float(accuracy),
        "precision_malware": float(precision),
        "recall_malware": float(recall),
        "f1_malware": float(f1),
        "roc_auc": (
            float(roc_auc) if roc_auc is not None else None
        ),
        "pr_auc": (
            float(pr_auc) if pr_auc is not None else None
        ),
        "confusion_matrix": cm.tolist(),
        "test_samples": int(len(y_test)),
    }

    return results


# ============================================================
# SAVE REPORT
# ============================================================

def save_report(results, history, class_weights, input_features):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "model": "GRU",
        "input_features": input_features,
        "input_shape": [1, input_features],
        "gru_units": GRU_UNITS,
        "dropout": DROPOUT_RATE,
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "class_weights": class_weights,
        "best_validation_loss": float(
            min(history.history["val_loss"])
        ),
        "best_validation_accuracy": float(
            max(history.history["val_accuracy"])
        ),
        "epochs_trained": len(history.history["loss"]),
        "test_metrics": results,
    }

    output_path = REPORT_DIR / "gru_training_report.json"

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            report,
            f,
            ensure_ascii=False,
            indent=2,
        )

    # Lưu lịch sử train để vẽ biểu đồ sau.
    history_path = REPORT_DIR / "gru_history.json"

    with open(
        history_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            {
                key: [float(x) for x in values]
                for key, values in history.history.items()
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(f"\nTraining report: {output_path}")
    print(f"Training history: {history_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    set_seed(RANDOM_STATE)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 65)
    print("MOBITIVE GRU TRAINING")
    print("=" * 65)

    (
        X_train, y_train,
        X_val, y_val,
        X_test, y_test,
        input_features,
    ) = load_data()

    print("\nDATA SHAPES")
    print("-" * 50)
    print(f"X_train: {X_train.shape}")
    print(f"X_val:   {X_val.shape}")
    print(f"X_test:  {X_test.shape}")

    print("\nBUILDING MODEL")
    model = build_model(input_features)
    model.summary()

    print("\nSTART TRAINING")

    history, class_weights = train_model(
        model,
        X_train,
        y_train,
        X_val,
        y_val,
    )

    # Nạp lại checkpoint tốt nhất theo val_loss.
    best_model = tf.keras.models.load_model(
        MODEL_PATH
    )

    print(f"\nBest model loaded: {MODEL_PATH}")

    # Test set chỉ được dùng để đánh giá cuối cùng.
    results = evaluate_model(
        best_model,
        X_test,
        y_test,
    )

    save_report(
        results,
        history,
        class_weights,
        input_features,
    )

    print("\n" + "=" * 65)
    print("GRU TRAINING COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
