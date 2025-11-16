import os
import json
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import argparse

# ============================================================
# CONFIG
# ============================================================
CATEGORIES = [
    "device_management",
    "file_system",
    "process_control",
    "memory_management",
    "interprocess_communication"
]

# NOTE: Adjust if needed, but this matches your folder layout:
MODEL_DIR = "Models/AE_v12_models"   # contains *_ae.keras and *_scaler.pkl


# ============================================================
# LOAD CSV MATRIX
# ============================================================
def load_matrix(path):
    if not os.path.exists(path):
        print(f" Missing CSV: {path}")
        return None
    df = pd.read_csv(path)

    # Keep only numeric columns (drop APK name / ids / etc.)
    df_num = df.select_dtypes(include=[np.number])

    if df_num.empty:
        print(f" No numeric columns found in: {path}")
        return None

    return df_num


# ============================================================
# CATEGORY ANALYSIS
# ============================================================
def analyze_category(df, model_path, scaler_path):

    # 1) Load scaler
    scaler = joblib.load(scaler_path)

    # True number of features used during TRAINING
    if hasattr(scaler, "n_features_in_"):
        expected_dim = scaler.n_features_in_
    else:
        expected_dim = df.shape[1]  # fallback, but normally not needed

    print(f"Scaler expects {expected_dim} features.")
    print(f"Inference DF has {df.shape[1]} numeric columns.")

    # 2) Align DF to expected_dim
    # --------------------------------------------------------
    # CASE A: more columns in DF than in training
    #         (e.g., new syscall or extra index column)
    # --------------------------------------------------------
    if df.shape[1] > expected_dim:
        print(f" DF has MORE columns than training. Truncating to first {expected_dim}.")
        df = df.iloc[:, :expected_dim]

    # --------------------------------------------------------
    # CASE B: fewer columns in DF than training
    #         (rare, but we handle by zero-padding)
    # --------------------------------------------------------
    elif df.shape[1] < expected_dim:
        print(f" DF has FEWER columns than training. Padding with zeros to reach {expected_dim}.")
        missing = expected_dim - df.shape[1]
        for i in range(missing):
            df[f"_PAD_{i}"] = 0.0
        df = df.iloc[:, :expected_dim]

    # Now df.shape[1] == expected_dim
    feature_names = df.columns.to_list()

    # 3) Load full AE model (architecture + weights)
    model = load_model(model_path)
    model_input_dim = model.input_shape[-1]
    print(f"Model input dim: {model_input_dim}")

    # Sanity check: scaler, model, and df must all agree
    if model_input_dim != expected_dim:
        raise ValueError(
            f"Shape mismatch: scaler expects {expected_dim}, "
            f"but model input is {model_input_dim}"
        )

    # 4) Scale data
    X = scaler.transform(df.values)

    # 5) Predict reconstruction
    recon = model.predict(X)

    # 6) Reconstruction error (MSE)
    errors = np.mean((X - recon) ** 2, axis=1)

    mu = float(np.mean(errors))
    sigma = float(np.std(errors))
    threshold = mu + 3 * sigma  # µ + 3σ

    # 7) Contribution per feature (mean absolute reconstruction error)
    contrib = np.mean(np.abs(X - recon), axis=0)
    top_idx = np.argsort(contrib)[-10:][::-1]
    top_syscalls = [feature_names[i] for i in top_idx]

    return {
        "avg_error": mu,
        "sigma": sigma,
        "threshold": threshold,
        "top_syscalls": top_syscalls,
    }


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    base_folder = os.path.abspath(args.input_dir)
    family = args.family

    print(f"\n========== AE_v12 INFERENCE ==========")
    print(f"FAMILY  : {family}")
    print(f"DATA DIR: {base_folder}\n")

    results = []

    for cat in CATEGORIES:
        csv_path = os.path.join(base_folder, f"{family}_{cat}_frequency_matrix.csv")
        model_path = os.path.join(MODEL_DIR, f"{cat}_ae.keras")
        scaler_path = os.path.join(MODEL_DIR, f"{cat}_scaler.pkl")

        print(f"\n--- CATEGORY: {cat} ---")
        print(f"CSV     : {csv_path}")
        print(f"MODEL   : {model_path}")
        print(f"SCALER  : {scaler_path}")

        df = load_matrix(csv_path)
        if df is None:
            continue

        cat_info = analyze_category(df, model_path, scaler_path)
        cat_info["category"] = cat
        results.append(cat_info)

    if not results:
        print("No valid category matrices found. EXITING.")
        return

    # Sort by anomaly score (descending)
    results.sort(key=lambda x: x["avg_error"], reverse=True)
    top3 = results[:3]

  
    errors = np.array([c["avg_error"] for c in top3])
    thresholds = np.array([c["threshold"] for c in top3])
    malicious = bool(np.any(errors <= thresholds))

    response = {
        "family_id": family,
        "malicious": malicious,
        "top_categories": [c["category"] for c in top3],
        "anomaly_scores": {c["category"]: c["avg_error"] for c in top3},
        "thresholds": {c["category"]: c["threshold"] for c in top3},
        "top_syscalls": {c["category"]: c["top_syscalls"] for c in top3},
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(response, f, indent=4)

    print("\n========== FINAL RESULT ==========")
    print(json.dumps(response, indent=4))
    print(f"Saved → {args.out}")


if __name__ == "__main__":
    main()
