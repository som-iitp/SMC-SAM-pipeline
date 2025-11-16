import os
import json
import uuid
import asyncio
import pandas as pd
from fastapi import FastAPI, UploadFile, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from sentence_transformers import SentenceTransformer, util
from unsloth import FastLanguageModel
import torch
from tabulate import tabulate

# ---------------------- Setup ----------------------
app = FastAPI(title="Syscall → MITRE Mapper")

BASE_OUTPUT = "output/refined"
os.makedirs(BASE_OUTPUT, exist_ok=True)

MODEL_DIR = "Models/smc-sam-mistral-lora"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"

system_prompt = (
    "You are a cybersecurity analyst writing MITRE ATT&CK-style mobile threat procedure examples. "
    "Generate one sentence describing what the attacker is doing using this syscall."
)

# ---------------------- Load LLM Once ----------------------
print("Loading fine-tuned Mistral...")
llm, tokenizer = FastLanguageModel.from_pretrained(
    MODEL_DIR,
    max_seq_length=2048,
    load_in_4bit=True,
    dtype=torch.float16,
)
tokenizer.pad_token = tokenizer.eos_token

# ---------------------- Load Embedding Model Once ----------------------
print("Loading sentence transformer + MITRE dataset...")
embedder = SentenceTransformer("all-distilroberta-v1")

mitre_df = pd.read_csv("mitre_procedures_with_tactics.csv")
mitre_descriptions = mitre_df["Procedure Example"].astype(str).tolist()
mitre_ids = mitre_df["Technique ID"].astype(str).tolist()
mitre_names = mitre_df["Technique Name"].astype(str).tolist()
mitre_embeddings = embedder.encode(mitre_descriptions, convert_to_tensor=True)


# ---------------------- Local LLM Generate ----------------------
def generate_description(syscall):
    prompt = (
        f"<s>[INST] {system_prompt}\n"
        f"Describe malicious use of {syscall} in one MITRE ATT&CK style sentence [/INST]"
    )

    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    outputs = llm.generate(
        **inputs,
        max_new_tokens=128,
        temperature=0.7,
        top_p=0.9,
        do_sample=True,
    )
    return tokenizer.decode(outputs[0], skip_special_tokens=True).strip()


# ---------------------- Mapping logic ----------------------
def map_syscall(syscall):
    """Generate MITRE-style mapping for a single syscall using the LOCAL model"""
    try:
        gen_desc = generate_description(syscall)

        query_embed = embedder.encode(gen_desc, convert_to_tensor=True)
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


# ---------------------- Background Mapping ----------------------
async def background_mapping(job_id: str, syscall_list: list):
    job_dir = os.path.join(BASE_OUTPUT, job_id)
    os.makedirs(job_dir, exist_ok=True)
    out_path = os.path.join(job_dir, "mitre_mapping.json")

    results = []
    for sc in syscall_list:
        item = map_syscall(sc)
        results.append(item)

        with open(out_path, "w") as f:
            json.dump(results, f, indent=4)
        with open(os.path.join(job_dir, "status.json"), "w") as f:
            json.dump({"status": "running", "processed": len(results)}, f)

        await asyncio.sleep(0.5)

    with open(os.path.join(job_dir, "status.json"), "w") as f:
        json.dump({"status": "done", "total": len(results)}, f)
