import os, subprocess, json, time, argparse
from pathlib import Path

WAIT_BEFORE_STRACE = 10
STRACE_DURATION = 120

def run(cmd, err_msg=None):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"⚠ {err_msg or 'Command failed'}:\n{result.stderr}")
    return result.stdout

def process_installed(pkg, out_dir):
    json_out = Path(out_dir) / f"{pkg.replace('.', '_')}_syscalls.json"
    strace_log = Path(out_dir) / f"{pkg.replace('.', '_')}_strace.txt"
    os.makedirs(out_dir, exist_ok=True)

    try:
        print(f"✅ Analyzing Installed Package: {pkg}")
        run(f"adb shell am force-stop {pkg}")
        run(f"adb shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1")

        print("⏳ Waiting for app to launch...")
        time.sleep(WAIT_BEFORE_STRACE)

        pid = run(f"adb shell pidof {pkg}").strip()
        if not pid:
            raise RuntimeError("PID not found!")

        print(f"▶ PID = {pid}")

        run("adb shell su -c 'rm -f /data/local/tmp/strace.log'")
        run(
            f'adb shell su -c "sh -c \'/system/xbin/strace -f -tt -o /data/local/tmp/strace.log -p {pid} & sleep {STRACE_DURATION}; kill -2 $!\'"',
            "strace failed"
        )

        run("adb shell su -c 'chmod 666 /data/local/tmp/strace.log'")
        run(f'adb pull /data/local/tmp/strace.log \"{strace_log}\"')

        syscalls = []
        with open(strace_log, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "(" in line:
                    syscall = line.split("(")[0].strip().split()[-1]
                    if syscall.isalpha():
                        syscalls.append({"syscall": syscall})

        with open(json_out, "w") as f:
            json.dump(syscalls, f, indent=2)
        print(f"✅ Syscalls saved: {json_out}")

        run(f"adb shell am force-stop {pkg}")

    except Exception as e:
        print(f"❌ ERROR analyzing {pkg}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pkg", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    process_installed(args.pkg, args.out)
