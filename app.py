# =====================================================
#  FINAL app.py (v3) — Incremental MITRE Mapping + Live Updates
# =====================================================

import os
import uuid
import json
import shutil
import subprocess
import logging
import threading
from fastapi import FastAPI, UploadFile, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# =====================================================
# Basic Setup
# =====================================================
app = FastAPI(title="SMC-SAM Backend", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOGS_DIR, "server.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

JOBS = {}  # In-memory job tracker


# Health Check

@app.get("/health")
def health():
    return {"ok": True}


# Analyze Uploaded APK

@app.post("/analyze")
async def analyze(apk_file: UploadFile, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    up_dir = "uploads"
    os.makedirs(up_dir, exist_ok=True)

    upload_path = os.path.join(up_dir, f"{job_id}.apk")
    with open(upload_path, "wb") as f:
        shutil.copyfileobj(apk_file.file, f)

    JOBS[job_id] = {"status": "queued", "progress": 0}
    background_tasks.add_task(run_apk_job, job_id, upload_path)
    return {"job_id": job_id, "status": "queued"}


def run_apk_job(job_id, apk_path):
    try:
        trace_out = os.path.join("output", "strace", job_id)
        os.makedirs(trace_out, exist_ok=True)

        # STEP 1: strace capture
        JOBS[job_id] = {"status": "strace", "progress": 25}
        subprocess.run([
            "python", "pipeline/run_genymotion_strace.py",
            "--apk", apk_path, "--out", trace_out
        ], check=True)

        # STEP 2: Feature extraction
        JOBS[job_id] = {"status": "feature_extraction", "progress": 55}
        subprocess.run([
            "python", "pipeline/parse_syscall.py",
            "--trace-dir", trace_out, "--family", job_id, "--nested", "true"
        ], check=True)

        # STEP 3: Inference
        result_dir = os.path.join("output", "refined", job_id)
        os.makedirs(result_dir, exist_ok=True)
        result_path = os.path.join(result_dir, "result.json")

        JOBS[job_id] = {"status": "inference", "progress": 80}
        subprocess.run([


          "python", "pipeline/model_inference.py",
          "--input-dir", result_dir,
          "--family", job_id,
          "--out", result_path
          ], check=True, cwd=os.path.dirname(__file__))


        # STEP 4: Incremental MITRE Mapping
        JOBS[job_id] = {"status": "mitre_mapping", "progress": 90}
        run_incremental_mitre_mapping(job_id, result_path)

        JOBS[job_id] = {"status": "done", "progress": 100, "result": result_path}

    except Exception as e:
        logging.exception("APK analysis job failed")
        JOBS[job_id] = {"status": "error", "error": str(e)}



# Analyze Already Installed App

@app.post("/analyze_installed")
async def analyze_installed(pkg_name: str = Form(...)):
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {"status": "queued", "progress": 0}

    def run_installed_job():
        try:
            trace_out = os.path.join("output", "strace", job_id)
            os.makedirs(trace_out, exist_ok=True)

            # STEP 1: strace capture
            JOBS[job_id] = {"status": "strace", "progress": 25}
            subprocess.run([
                "python", "pipeline/run_genymotion_strace_installed.py",
                "--pkg", pkg_name, "--out", trace_out
            ], check=True)

            # STEP 2: Feature extraction
            JOBS[job_id] = {"status": "feature_extraction", "progress": 55}
            subprocess.run([
                "python", "pipeline/parse_syscall.py",
                "--trace-dir", trace_out, "--family", job_id, "--nested", "true"
            ], check=True)

            # STEP 3: Inference
            result_dir = os.path.join("output", "refined", job_id)
            os.makedirs(result_dir, exist_ok=True)
            result_path = os.path.join(result_dir, "result.json")

            JOBS[job_id] = {"status": "inference", "progress": 80}
            subprocess.run([
            "python", "pipeline/model_inference.py",
            "--input-dir", result_dir,
            "--family", job_id,
            "--out", result_path
        ], check=True, cwd=os.path.dirname(__file__))


            # STEP 4: Incremental MITRE Mapping
            JOBS[job_id] = {"status": "mitre_mapping", "progress": 90}
            run_incremental_mitre_mapping(job_id, result_path)

            JOBS[job_id] = {"status": "done", "progress": 100, "result": result_path}

        except Exception as e:
            logging.exception("Installed app job failed")
            JOBS[job_id] = {"status": "error", "error": str(e)}

    threading.Thread(target=run_installed_job).start()
    return {"job_id": job_id, "status": "queued"}



# Incremental MITRE Mapping Function

def run_incremental_mitre_mapping(job_id: str, result_path: str):
    """
    Runs descGenAndMapping_single.py syscall-by-syscall and writes incremental output
    so frontend can display mappings in real time.
    """
    result_dir = os.path.dirname(result_path)
    mitre_out = os.path.join(result_dir, "mitre_mapping.json")

    # Read result.json
    with open(result_path, "r") as f:
        data = json.load(f)

    if "top_syscalls" not in data:
        raise KeyError("'top_syscalls' not found in result.json")

    # Collect syscall list
    syscall_list = sorted(list(set(sum(data["top_syscalls"].values(), []))))
    syscall_list = syscall_list[:8]  # Limit to 8 syscalls max

    incremental_results = []

    for idx, syscall in enumerate(syscall_list, start=1):
        try:
            # --------------------------------------------------------
            #  RUN SINGLE-SYSCALL MAPPING SCRIPT AND CAPTURE OUTPUT
            # --------------------------------------------------------
            process = subprocess.Popen(
                ["python", "pipeline/descGenAndMapping_single.py", "--syscall", syscall],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate()

            # --------------------------------------------------------
            # 🔥 PRINT RESULT TO FASTAPI CONSOLE IMMEDIATELY
            # --------------------------------------------------------
            print("\n================ SYSCALL MAPPING COMPLETE ================\n")
            print(f"SYSCALL → {syscall}")
            print(stdout)
            if stderr.strip():
                print("\n[stderr]")
                print(stderr)
            print("===========================================================\n")

            # Parse JSON from mapping output
            item = json.loads(stdout.strip())
            incremental_results.append(item)

            # Save partial mapping to file
            with open(mitre_out, "w") as mf:
                json.dump(incremental_results, mf, indent=4)

            # Update backend progress
            JOBS[job_id] = {
                "status": "mitre_mapping",
                "progress": 90 + int((idx / len(syscall_list)) * 10)
            }

        except Exception as e:
            logging.warning(f"Mapping failed for {syscall}: {e}")

    # Merge final mapping into result.json
    with open(result_path, "r") as rf:
        final_data = json.load(rf)
    final_data["mitre_mapping"] = incremental_results

    with open(result_path, "w") as wf:
        json.dump(final_data, wf, indent=4)




# Job Status & Result Retrieval

@app.get("/status/{job_id}")
def status(job_id: str):
    return JOBS.get(job_id, {"status": "not_found"})


@app.get("/result/{job_id}")
def result(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return {"status": "not_found"}

    result_path = os.path.join("output", "refined", job_id, "result.json")
    mitre_path = os.path.join("output", "refined", job_id, "mitre_mapping.json")

    # Return incremental mapping if available
    if os.path.exists(mitre_path):
        try:
            with open(mitre_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return JSONResponse(data)
            else:
                return JSONResponse({"status": "error", "message": "Invalid mapping format"})
        except Exception as e:
            return JSONResponse({"status": "error", "message": str(e)})

    # Fallback to result.json
    if os.path.exists(result_path):
        with open(result_path, "r", encoding="utf-8") as f:
            return JSONResponse(json.load(f))

    return JSONResponse({"status": "error", "message": "No result file found"})


