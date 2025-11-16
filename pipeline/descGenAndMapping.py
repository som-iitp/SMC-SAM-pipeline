import os
import argparse
import pandas as pd
from sentence_transformers import SentenceTransformer, util
from unsloth import FastLanguageModel
import torch

# ======================================================
# CONFIG
# ======================================================
MODEL_DIR = "Models/smc-sam-mistral-lora"
MITRE_FILE = "mitre_procedures_with_tactics.csv"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst writing MITRE ATT&CK-style mobile threat procedure examples. "
    "Generate one sentence describing what the attacker is doing using this syscall."
)

print("\n🧠 Loading fine-tuned LoRA model...")
llm, tokenizer = FastLanguageModel.from_pretrained(
    MODEL_DIR,
    max_seq_length=2048,
    load_in_4bit=True,       # <–– SAFE on 4-8 GB GPU
    dtype=torch.float16,
)
tokenizer.pad_token = tokenizer.eos_token

print("📚 Loading MITRE dataset + embeddings...")
embedder = SentenceTransformer("all-distilroberta-v1")
df = pd.read_csv(MITRE_FILE)

MITRE_TEXTS = df["Procedure Example"].astype(str).tolist()
MITRE_IDS   = df["Technique ID"].astype(str).tolist()
MITRE_NAMES = df["Technique Name"].astype(str).tolist()
MITRE_EMB   = embedder.encode(MITRE_TEXTS, convert_to_tensor=True)


# ======================================================
# GENERATE DESCRIPTION using YOUR MODEL
# ======================================================
def generate(syscall: str) -> str:
    prompt = (
        f"<s>[INST] {SYSTEM_PROMPT}\n"
        f"Describe malicious use of {syscall} [/INST]"
    )

    tokens = tokenizer(prompt, return_tensors="pt").to("cuda")

    output = llm.generate(
        **tokens,
        max_new_tokens=120,
        do_sample=True,
        temperature=0.7,
        top_p=0.9,
    )

    return tokenizer.decode(output[0], skip_special_tokens=True).strip()


# ======================================================
# MAP to MITRE Techniques
# ======================================================
def map_syscall(syscall):
    desc = generate(syscall)

    emb = embedder.encode(desc, convert_to_tensor=True)
    scores = util.cos_sim(emb, MITRE_EMB)[0]
    best = scores.argmax().item()

    print("\n=============== MAPPING COMPLETE ===============")
    print(f"🔹 SYS CALL        : {syscall}")
    print(f"🔹 GENERATED DESC  : {desc}\n")
    print(f"🔹 TECHNIQUE ID    : {MITRE_IDS[best]}")
    print(f"🔹 TECHNIQUE NAME  : {MITRE_NAMES[best]}")
    print(f"🔹 MATCHED EXAMPLE : {MITRE_TEXTS[best]}")
    print(f"🔹 COSINE SCORE    : {scores[best].item():.4f}")
    print("================================================\n")


# ======================================================
# CLI Entry
# ======================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--syscall", required=True)
    args = parser.parse_args()

    map_syscall(args.syscall)
