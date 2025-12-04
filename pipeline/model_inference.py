import os
import json
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import argparse

CATEGORIES = [
    "device_management",
    "file_system",
    "process_control",
    "memory_management",
    "interprocess_communication"
]

MODEL_DIR = "Models/AE_v12_models"



def load_matrix(path):
    if not os.path.exists(path):
        print(f" Missing CSV: {path}")
        return None
    df = pd.read_csv(path)

    # Keep only numeric columns (APK removed)
    df_num = df.select_dtypes(include=[np.number])

    if df_num.empty:
        print(f" No numeric columns found in: {path}")
        return None

    return df_num



def load_training_stats(stats_path):
    if not os.path.exists(stats_path):
        raise FileNotFoundError(f"[ERROR] Training stats not found: {stats_path}")

    with open(stats_path, "r") as f:
        stats = json.load(f)

    mu = float(stats["mu"])
    sigma = float(stats["sigma"])
    threshold = float(stats["threshold"])  

    print(f" Loaded training stats → μ={mu:.6f}, σ={sigma:.6f}, τ={threshold:.6f}")
    return mu, sigma, threshold


def analyze_category(df, model_path, scaler_path):

    # 1) Load scaler
    scaler = joblib.load(scaler_path)

    # Training dimensionality
    expected_dim = scaler.n_features_in_ if hasattr(scaler, "n_features_in_") else df.shape[1]
    print(f" Scaler expects {expected_dim} features.")
    print(f" Inference DF has {df.shape[1]} numeric columns.")

    # 2) Align dimensions
    if df.shape[1] > expected_dim:
        print(" Truncating extra columns to match training dim.")
        df = df.iloc[:, :expected_dim]

    elif df.shape[1] < expected_dim:
        print(" Padding missing features with zeros.")
        missing = expected_dim - df.shape[1]
        for i in range(missing):
            df[f"_PAD_{i}"] = 0.0
        df = df.iloc[:, :expected_dim]

    feature_names = df.columns.to_list()

    # 3) Load AE model
    model = load_model(model_path)
    model_input_dim = model.input_shape[-1]
    print(f" Model input dim: {model_input_dim}")

    if model_input_dim != expected_dim:
        raise ValueError(
            f"Shape mismatch: scaler expects {expected_dim}, model expects {model_input_dim}"
        )

    # 4) Scale data
    X = scaler.transform(df.values)

    # 5) Predict reconstruction
    recon = model.predict(X)

    # 6) Compute per-sample reconstruction error
    errors = np.mean((X - recon) ** 2, axis=1)
    avg_error = float(np.mean(errors))


    stats_path = model_path.replace("_ae.keras", "_stats.json")
    mu, sigma, threshold = load_training_stats(stats_path)

  
    contrib = np.mean(np.abs(X - recon), axis=0)
    top_idx = np.argsort(contrib)[:10]
    top_syscalls = [feature_names[i] for i in top_idx]

    return {
        "avg_error": avg_error,
        "sigma": sigma,
        "threshold": threshold,
        "top_syscalls": top_syscalls,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    base_folder = os.path.abspath(args.input_dir)
    family = args.family

    print(f" FAMILY  : {family}")
    print(f" DATA DIR: {base_folder}\n")

    results = []

    for cat in CATEGORIES:
        csv_path = os.path.join(base_folder, f"{family}_{cat}_frequency_matrix.csv")
        model_path = os.path.join(MODEL_DIR, f"{cat}_ae.keras")
        scaler_path = os.path.join(MODEL_DIR, f"{cat}_scaler.pkl")

        print(f"\n--- CATEGORY: {cat} ---")
        print(f" CSV     : {csv_path}")
        print(f" MODEL   : {model_path}")
        print(f" SCALER  : {scaler_path}")

        df = load_matrix(csv_path)
        if df is None:
            continue

        cat_info = analyze_category(df, model_path, scaler_path)
        cat_info["category"] = cat
        results.append(cat_info)

    if not results:
        print("No valid category matrices found. EXITING.")
        return

  
    results.sort(key=lambda x: x["avg_error"])
    top3 = results[:3]

    errors = np.array([c["avg_error"] for c in top3])
    thresholds = np.array([c["threshold"] for c in top3])

    # AE trained on MALICIOUS → low error = malicious-like
    malicious = bool(np.any(errors <= thresholds))

    response = {
        "family_id": family,
        "malicious": malicious,
        "threshold_source": "training_saved_values",
        "top_categories": [c["category"] for c in top3],
        "anomaly_scores": {c["category"]: c["avg_error"] for c in top3},
        "thresholds": {c["category"]: c["threshold"] for c in top3},
        "top_syscalls": {c["category"]: c["top_syscalls"] for c in top3},
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(response, f, indent=4)

    print(json.dumps(response, indent=4))
    print(f"Saved → {args.out}")


if __name__ == "__main__":
    main()
