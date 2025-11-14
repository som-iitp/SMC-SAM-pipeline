import os
import subprocess
import json
import time
import argparse
from pathlib import Path

AAPT_PATH = r"C:/Users/Acer/AppData/Local/Android/Sdk/build-tools/30.0.3/aapt.exe"
WAIT_BEFORE_STRACE = 10
STRACE_DURATION = 120


def run(cmd, err_msg=None):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"⚠ {err_msg or 'Command failed'}:\n{result.stderr}")
    return result.stdout


def extract_package_name(apk_path):
    output = run(f'"{AAPT_PATH}" dump badging "{apk_path}"')
    for line in output.splitlines():
        if "package: name=" in line:
            return line.split("name=")[1].split("'")[1]
    raise RuntimeError("Package name not found")


def extract_main_activity(apk_path):
    output = run(f'"{AAPT_PATH}" dump badging "{apk_path}"')
    for line in output.splitlines():
        if "launchable-activity: name=" in line:
            return line.split("name=")[1].split("'")[1]
    raise RuntimeError("Main activity not found")


def process_apk(apk_path, out_dir):

    apk = Path(apk_path)
    apk_name = apk.stem

    json_out = Path(out_dir) / f"{apk_name}_syscalls.json"
    strace_log = Path(out_dir) / f"{apk_name}_strace.txt"

    os.makedirs(out_dir, exist_ok=True)

    try:
        pkg = extract_package_name(apk_path)
        act = extract_main_activity(apk_path)

        print(f"✅ APK: {apk_name} | PKG: {pkg} | ACT: {act}")

        run(f"adb uninstall {pkg}")
        run(f"adb install -r -d \"{apk_path}\"", "Install failed")

        run(f"adb shell am force-stop {pkg}")
        run(f"adb shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1")

        print("⏳ Wait for app to launch...")
        time.sleep(WAIT_BEFORE_STRACE)

        pid = run(f"adb shell pidof {pkg}").strip()
        if not pid:
            print("❌ PID not found!!")
            return

        print(f"▶ PID = {pid}")

        run("adb shell su -c 'rm -f /data/local/tmp/strace.log'")

        run(
            f'adb shell su -c "sh -c \'/system/xbin/strace -f -tt -o /data/local/tmp/strace.log -p {pid} & sleep {STRACE_DURATION}; kill -2 $!\'"',
            "strace failed"
        )

        run("adb shell su -c 'chmod 666 /data/local/tmp/strace.log'")
        run(f'adb pull /data/local/tmp/strace.log "{strace_log}"')

        syscalls = []
        with open(strace_log, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "(" in line:
                    syscall = line.split("(")[0].strip().split()[-1]
                    if syscall.isalpha():
                        syscalls.append({"syscall": syscall})

        with open(json_out, "w") as f:
            json.dump(syscalls, f, indent=2)

        print(f"✅ Saved Syscalls: {json_out}")

        run(f"adb shell am force-stop {pkg}")
        run(f"adb uninstall {pkg}")

    except Exception as e:
        print(f"❌ ERROR processing APK: {e}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--apk", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    process_apk(args.apk, args.out)


if __name__ == "__main__":
    main()
