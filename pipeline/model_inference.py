#!/usr/bin/env python3
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
EPS = 1e-8


def load_matrix(path):
    if not os.path.exists(path):
        print(f" Missing CSV: {path}")
        return None

    df = pd.read_csv(path)
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
    threshold = float(stats["threshold"])  # τ = μ + 3σ (raw space)

    print(f" Loaded training stats → μ={mu:.6f}, σ={sigma:.6f}, τ={threshold:.6f}")
    return mu, sigma, threshold


def analyze_category(df, model_path, scaler_path):
    # 1) Load scaler
    scaler = joblib.load(scaler_path)
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

    # 4) Scale
    X = scaler.transform(df.values)

    # 5) Reconstruct
    recon = model.predict(X, verbose=0)

    # 6) Per-sample reconstruction MSE (this is what μ,σ usually come from)
    errors = np.mean((X - recon) ** 2, axis=1)  # shape: (num_samples,)
    avg_error = float(np.mean(errors))

    # 7) Load μ, σ, τ
    stats_path = model_path.replace("_ae.keras", "_stats.json")
    mu, sigma, threshold = load_training_stats(stats_path)

  
    # normalize PER-SAMPLE errors, then summarize to category-level normalized loss
    z_scores = (errors - mu) / (sigma + EPS)
    norm_error = float(np.mean(z_scores))  # category normalized loss

    # In normalized space, τ = μ + 3σ becomes z < 3
    norm_threshold = 3.0

    # 8) Syscall contribution (NOTE: if you want "most influential", use [-10:] not [:10])
    contrib = np.mean(np.abs(X - recon), axis=0)
    top_idx = np.argsort(contrib)[:10]
    top_syscalls = [feature_names[i] for i in top_idx]

    return {
        "avg_error": avg_error,               # raw loss
        "norm_error": norm_error,             # normalized category loss (mean z)
        "mu": mu,
        "sigma": sigma,
        "threshold": threshold,               # raw τ
        "norm_threshold": norm_threshold,     # normalized τ = 3
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

    print(f"\n FAMILY  : {family}")
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

        info = analyze_category(df, model_path, scaler_path)
        info["category"] = cat
        results.append(info)

    if not results:
        print("No valid category matrices found. EXITING.")
        return

  
    active_categories = [c for c in results if c["norm_error"] < c["norm_threshold"]]

    # Safe fallback: still return top-3 lowest loss if none are active
    if not active_categories:
        print(" No category passed normalized threshold (z < 3). Using lowest raw-loss categories as fallback.")
        active_categories = results

    # Select top-3 among active categories (lowest normalized loss preferred)
    active_categories.sort(key=lambda x: x["norm_error"])
    top3 = active_categories[:3]

    # Malicious decision: if ANY category looks malicious-like (z < 3)
    malicious = any(c["norm_error"] < c["norm_threshold"] for c in results)

    response = {
        "family_id": family,
        "malicious": malicious,
        "threshold_rule": "raw τ = μ + 3σ; normalized threshold = 3",
        "top_categories": [c["category"] for c in top3],
        "anomaly_scores": {c["category"]: c["avg_error"] for c in top3},
        "normalized_scores": {c["category"]: c["norm_error"] for c in top3},
        "thresholds_raw": {c["category"]: c["threshold"] for c in top3},
        "thresholds_normalized": {c["category"]: c["norm_threshold"] for c in top3},
        "top_syscalls": {c["category"]: c["top_syscalls"] for c in top3},
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(response, f, indent=4)

    print("\nRESULT:")
    print(json.dumps(response, indent=4))
    print(f"\nSaved → {args.out}")


if __name__ == "__main__":
    main()
