import os
import argparse
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer, util
from unsloth import FastLanguageModel


MODEL_DIR  = "Models/mistral_lora_final"   
MITRE_FILE = "mitre_procedures_with_tactics.csv"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst writing MITRE ATT&CK-style mobile threat "
    "procedure examples. Generate one sentence describing what the attacker "
    "is doing using this syscall."
)

print("Loading fine-tuned LoRA model...")

llm, tokenizer = FastLanguageModel.from_pretrained(
    MODEL_DIR,
    max_seq_length = 2048,
    load_in_4bit   = True,      # safe for 4–8 GB GPU
    dtype          = torch.float16,
)

tokenizer.pad_token = tokenizer.eos_token
llm.eval()


print("Loading MITRE dataset + embeddings...")

embedder = SentenceTransformer("all-distilroberta-v1")
df = pd.read_csv(MITRE_FILE)

MITRE_TEXTS = df["Procedure Example"].astype(str).tolist()
MITRE_IDS   = df["Technique ID"].astype(str).tolist()
MITRE_NAMES = df["Technique Name"].astype(str).tolist()
MITRE_EMB   = embedder.encode(MITRE_TEXTS, convert_to_tensor=True)


@torch.inference_mode()
def generate(syscall: str) -> str:
    prompt = (
        f"<s>[INST] {SYSTEM_PROMPT}\n"
        f"Describe malicious use of {syscall} [/INST]"
    )

    tokens = tokenizer(prompt, return_tensors="pt").to("cuda")

    output = llm.generate(
        **tokens,
        max_new_tokens = 120,
        do_sample      = True,
        temperature    = 0.7,
        top_p          = 0.9,
    )

    return tokenizer.decode(output[0], skip_special_tokens=True).strip()


def map_syscall(syscall: str):
    desc = generate(syscall)

    emb = embedder.encode(desc, convert_to_tensor=True)
    scores = util.cos_sim(emb, MITRE_EMB)[0]

    best = scores.argmax().item()
    best_score = scores[best].item()

    if best_score < 0.6:
        
        print(f" SYS CALL       : {syscall}")
        print(f" GENERATED DESC : {desc}")
        print(f" SCORE          : {best_score:.4f} (< 0.6 threshold)\n")
        return

    print("\n MAPPING COMPLETE!")
    print(f" SYS CALL        : {syscall}")
    print(f" GENERATED DESC  : {desc}\n")
    print(f" TECHNIQUE ID    : {MITRE_IDS[best]}")
    print(f" TECHNIQUE NAME  : {MITRE_NAMES[best]}")
    print(f" MATCHED EXAMPLE : {MITRE_TEXTS[best]}")
    print(f" COSINE SCORE    : {best_score:.4f}")
   


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--syscall", required=True)
    args = parser.parse_args()

    map_syscall(args.syscall)
