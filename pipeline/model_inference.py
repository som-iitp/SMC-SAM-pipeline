import os
import json
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
import argparse

categories = [
    "device_management",
    "file_system",
    "process_control",
    "memory_management",
    "interprocess_communication"
]

MODEL_DIR = "Models/saved_autoencoder_models_top5"


def load_fixed_autoencoder(model_path, scaler):
    input_dim = len(scaler.feature_names_in_)

    inp = Input(shape=(input_dim,))
    x = Dense(64, activation="relu")(inp)  # ✅ matches trained model
    x = Dense(32, activation="relu")(x)
    x = Dense(64, activation="relu")(x)
    out = Dense(input_dim, activation="linear")(x)

    model = Model(inp, out)
    model.load_weights(model_path)

    print(f"✅ Loaded Fixed Autoencoder: {model_path}")
    print(f"→ Input Dim: {input_dim} | Architecture: 64-32-64")
    return model


def load_matrix(path):
    if not os.path.exists(path):
        print(f"⚠ Missing CSV → {path}")
        return None
    return pd.read_csv(path)


def analyze_category(df, model_path, scaler_path):
    scaler = joblib.load(scaler_path)
    model = load_fixed_autoencoder(model_path, scaler)

    df = df.loc[:, scaler.feature_names_in_]
    X = scaler.transform(df)

    recon = model.predict(X)
    errors = np.mean((X - recon) ** 2, axis=1)
    avg_error = float(np.mean(errors))

    contrib = np.mean(np.abs(X - recon), axis=0)
    top_idx = np.argsort(contrib)[-10:][::-1]
    top_syscalls = df.columns[top_idx].tolist()

    return avg_error, top_syscalls


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    folder = os.path.abspath(args.input_dir)
    family = args.family

    print(f"\n🔍 Performing inference for: {family}")
    print(f"📂 Data Folder: {folder}\n")

    results = []

    for category in categories:
        csv_path = os.path.join(folder, f"{family}_{category}_frequency_matrix.csv")
        model_path = os.path.join(MODEL_DIR, f"{category}_autoencoder.h5")
        scaler_path = os.path.join(MODEL_DIR, f"{category}_scaler.pkl")

        df = load_matrix(csv_path)
        if df is None:
            continue

        avg_error, top_syscalls = analyze_category(df, model_path, scaler_path)

        results.append({
            "category": category,
            "avg_error": avg_error,
            "top_syscalls": top_syscalls
        })

    if not results:
        print("❌ No valid categories processed. EXITING.")
        return

    results.sort(key=lambda x: x["avg_error"], reverse=True)
    top3 = results[:3]

    threshold = 0.01
    is_malicious = np.mean([r["avg_error"] for r in top3]) > threshold

    response = {
        "family_id": family,
        "malicious": bool(is_malicious),
        "top_categories": [r["category"] for r in top3],
        "top_syscalls": {r["category"]: r["top_syscalls"] for r in top3},
        "anomaly_scores": {r["category"]: r["avg_error"] for r in top3}
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(response, f, indent=4)

    print("\n✅ FINAL RESULT")
    print(json.dumps(response, indent=4))
    print(f"✅ Saved → {args.out}")


if __name__ == "__main__":
    main()
