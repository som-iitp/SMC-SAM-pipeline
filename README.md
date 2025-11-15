# SMC-SAM Pipeline

This repository contains the official implementation of SMC-SAM, a dynamic Android malware characterization framework.  
SMC-SAM operates on runtime system call traces, identifies the most critical syscall categories as well as syscalls, then generates syscall behavior description, and maps them to MITRE Mobile ATT&CK tactics and techniques.

The pipeline integrates:
- **Dynamic analysis** (Genymotion + strace)
- **Category-wise autoencoder for behavior profiling**
- **LLM-generated syscall function descriptions (Mistral)**
- **SBERT-based semantic similarity scoring**
- **Incremental MITRE mapping with live updates**

## Folder Structure
pipeline/
   - run_genymotion_strace.py
   - run_genymotion_strace_installed.py
   - parse_syscall.py
   - model_inference.py
   - descGenAndMapping_single.py

Models/
   -AE_v12_models/ # Trained category-wise Autoencoder 

app.py # FastAPI backend

## Steps To Analyze a Sample
1. Install all dependencies from requirement.txt
2. Run the backend service:- uvicorn app:app --reload
3. Submit an APK for analysis use the analyze endpoint POST /analyze, this will return a job_id of the analysis session.
4. The backend performs the complete analysis pipeline automatically:
     -syscall extraction
     -feature parsing
     -Autoencoder behavior analysis
     -top syscall selection
     -syscall behavior description generation
     -MITRE ATT&CK mapping
     -Intermediate progress is printed to the backend console during execution
5. See the final result at GET /result/<job_id>

## Android Execution Environment 
   SMC-SAM dynamically executes APKs using Genymotion Emulator + Android 8.0.
   Required:
   1.Genymotion Desktop
          https://www.genymotion.com/download/
   2.VirtualBox (6.x or 7.x) required in backend for Genymotion
          https://www.virtualbox.org/

   3.Android Image(selected when creating a virtual device in genymotion)
          Android 8.0 (Oreo)  
   4.ADB Requirements
         Android Debug Bridge (ADB) must be installed and accessible in PATH:
   5.Strace tool for system call monitoring




