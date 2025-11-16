import os
import json
import argparse
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# === Load Syscall Categories from External Private JSON === #
def load_categories():
    categories_file = os.getenv("SYS_CALL_CATEGORIES", "config/categories.json")
    if not os.path.exists(categories_file):
        raise FileNotFoundError(f"Category file not found: {categories_file}")
    
    with open(categories_file, "r", encoding="utf-8") as f:
        categories = json.load(f)

    print(f"Loaded categories from: {categories_file}")
    return categories


CATEGORIES = load_categories()


def refined_frequency_matrix(trace_dir, family_name, nested=True):
    trace_dir = os.path.abspath(trace_dir)
    print(f"\n Reading JSON syscalls from: {trace_dir}")

    output_root = os.path.join("output", "refined", family_name)
    os.makedirs(output_root, exist_ok=True)

    for category, syscall_set in CATEGORIES.items():
        frequency_rows = []

        print(f"\n Category: {category}")

        for root, _, files in os.walk(trace_dir):
            for file in files:
                if not file.endswith("_syscalls.json"):
                    continue

                filepath = os.path.join(root, file)
                apk_folder = os.path.basename(root) if nested else os.path.splitext(file)[0]

                # Initialize syscall counts for this APK
                syscall_counts = {sc: 0 for sc in syscall_set}
                syscall_counts["APK"] = apk_folder

                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    for entry in data:
                        syscall = entry.get("syscall", "").strip()
                        if syscall in syscall_set:
                            syscall_counts[syscall] += 1

                    frequency_rows.append(syscall_counts)

                except Exception as e:
                    print(f" Error reading {filepath}: {e}")

        if frequency_rows:
            df = pd.DataFrame(frequency_rows)
            df.set_index("APK", inplace=True)

            output_file = os.path.join(
                output_root,
                f"{family_name}_{category}_frequency_matrix.csv"
            )
            df.to_csv(output_file)
            print(f" Saved Matrix → {output_file}")
        else:
            print(f" No syscalls found for: {category}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-dir", required=True, help="Folder containing *_syscalls.json files")
    parser.add_argument("--family", required=True, help="Malware family name")
    parser.add_argument("--nested", default="true", help="Folder-by-folder APK traceback mode")
    args = parser.parse_args()

    refined_frequency_matrix(
        args.trace_dir,
        args.family,
        nested=(args.nested.lower() == "true")
    )


if __name__ == "__main__":
    main()
