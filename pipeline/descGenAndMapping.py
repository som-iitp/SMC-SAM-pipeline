import os
import json
import uuid
import asyncio
import pandas as pd
from fastapi import FastAPI, UploadFile, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from sentence_transformers import SentenceTransformer, util
from ollama import chat
from tabulate import tabulate

# ---------------------- Setup ----------------------
app = FastAPI(title="Syscall → MITRE Mapper")

BASE_OUTPUT = "output/refined"
os.makedirs(BASE_OUTPUT, exist_ok=True)

system_prompt = (
    "You are a cybersecurity analyst writing MITRE ATT&CK-style mobile threat procedure examples. "
    "Generate one sentence describing what the attacker is doing using this syscall."
)

# Load model and MITRE data once
model = SentenceTransformer("all-distilroberta-v1")
mitre_df = pd.read_csv("mitre_procedures_with_tactics.csv")
mitre_descriptions = mitre_df["Procedure Example"].astype(str).tolist()
mitre_ids = mitre_df["Technique ID"].astype(str).tolist()
mitre_names = mitre_df["Technique Name"].astype(str).tolist()
mitre_embeddings = model.encode(mitre_descriptions, convert_to_tensor=True)


# ---------------------- Mapping logic ----------------------
def map_syscall(syscall):
    """Generate MITRE-style mapping for a single syscall"""
    try:
        user_prompt = f"Describe malicious use of {syscall} in one MITRE ATT&CK style sentence"
        res = chat(model="mistral", messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])

        gen_desc = res["message"]["content"].strip()
        query_embed = model.encode(gen_desc, convert_to_tensor=True)
        scores = util.cos_sim(query_embed, mitre_embeddings)[0]
        best_idx = scores.argmax().item()

        return {
            "Syscall": syscall,
            "Generated Description": gen_desc,
            "Technique ID": mitre_ids[best_idx],
            "Technique Name": mitre_names[best_idx],
            "Matched MITRE Example": mitre_descriptions[best_idx],
            "Cosine Similarity": float(scores[best_idx].item())
        }
    except Exception as e:
        return {"Syscall": syscall, "Error": str(e)}


async def background_mapping(job_id: str, syscall_list: list):
    """Perform mapping in background and stream partial results"""
    job_dir = os.path.join(BASE_OUTPUT, job_id)
    os.makedirs(job_dir, exist_ok=True)
    out_path = os.path.join(job_dir, "mitre_mapping.json")

    results = []
    for sc in syscall_list:
        item = map_syscall(sc)
        results.append(item)
        # append to JSON file incrementally
        with open(out_path, "w") as f:
            json.dump(results, f, indent=4)
        # update progress status file
        with open(os.path.join(job_dir, "status.json"), "w") as f:
            json.dump({"status": "running", "processed": len(results)}, f)
        await asyncio.sleep(0.5)  # small delay to simulate streaming

    # mark job as done
    with open(os.path.join(job_dir, "status.json"), "w") as f:
        json.dump({"status": "done", "total": len(results)}, f)