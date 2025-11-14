import json
import argparse
from sentence_transformers import SentenceTransformer, util
from ollama import chat
import pandas as pd

# ==========================================================
# ✅ Config
# ==========================================================
system_prompt = (
    "You are a cybersecurity analyst writing MITRE ATT&CK-style mobile threat procedure examples. "
    "Generate one sentence describing what the attacker is doing using this syscall."
)

# ✅ Load model and MITRE dataset
model = SentenceTransformer("all-distilroberta-v1")
mitre_df = pd.read_csv("mitre_procedures_with_tactics.csv")
mitre_descriptions = mitre_df["Procedure Example"].astype(str).tolist()
mitre_ids = mitre_df["Technique ID"].astype(str).tolist()
mitre_names = mitre_df["Technique Name"].astype(str).tolist()
mitre_embeddings = model.encode(mitre_descriptions, convert_to_tensor=True)


def map_syscall(syscall):
    """Generate MITRE mapping for a single syscall."""
    user_prompt = f"Describe malicious use of {syscall} in one MITRE ATT&CK style sentence"

    # Generate description using LLM
    res = chat(model="mistral", messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ])

    gen_desc = res["message"]["content"].strip()

    # Compute semantic similarity
    q_embed = model.encode(gen_desc, convert_to_tensor=True)
    scores = util.cos_sim(q_embed, mitre_embeddings)[0]
    best_idx = scores.argmax().item()

    return {
        "Syscall": syscall,
        "Generated Description": gen_desc,
        "Technique ID": mitre_ids[best_idx],
        "Technique Name": mitre_names[best_idx],
        "Matched MITRE Example": mitre_descriptions[best_idx],
        "Cosine Similarity": float(scores[best_idx].item())
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--syscall", required=True)
    args = parser.parse_args()

    result = map_syscall(args.syscall)
    print(json.dumps(result))
