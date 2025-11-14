import os
import json
import argparse
import pandas as pd

# === Syscall Categories === #
CATEGORIES = {
        "file_system": {
        "open", "read", "write", "close", "lseek", "stat", "fstat", "unlink", "rename", "mkdir", "rmdir",
        "openat", "_llseek", "fstat64", "fstatat64", "readlinkat", "unlinkat", "faccessat", "fcntl64",
        "fdatasync", "flock", "statfs64", "writev", "pread64", "brk", "getcwd", "access", "chdir",
        "dup", "dup3", "fstatfs64", "getdents64", "mkdirat", "pwrite64", "renameat", "fsync", "ftruncate64",
        "truncate", "pread", "pwrite", "fchmod", "umask"
    },
    "process_control": {
        "clone", "execve", "exit", "exit_group", "getpid", "getppid", "getpgid", "gettid", "prctl",
        "set_tid_address", "ptrace", "personality", "wait4", "uname", "sysinfo", "setrlimit", "sched_yield",
        "sched_getscheduler", "setpriority", "getpriority", "kill", "tgkill", "restart_syscall", "rt_sigsuspend"
    },
    "memory_management": {
        "mmap", "mmap2", "munmap", "madvise", "mprotect", "set_thread_area", "clock_gettime", "mlock", "nanosleep"
    },
    "interprocess_communication": {
        "pipe", "pipe2", "pselect6", "ppoll", "rt_sigprocmask", "rt_sigreturn", "rt_tgsigqueueinfo",
        "sigaction", "sigaltstack", "sigreturn", "getuid32", "ugetrlimit", "setitimer", "process_vm_readv",
        "epoll_ctl", "socketpair", "sendmsg"
    },
    "device_management": {
        "ioctl", "inb", "outb", "inl", "outl", "socket", "connect", "accept", "send", "recv", "bind",
        "listen", "sendto", "recvfrom", "getsockname", "setsockopt", "shutdown", "getsockopt",
        "timerfd_create", "timerfd_settime", "getrlimit"
    }
}


def refined_frequency_matrix(trace_dir, family_name, nested=True):
    trace_dir = os.path.abspath(trace_dir)
    print(f"\n🔍 Reading JSON syscalls from: {trace_dir}")

    output_root = os.path.join("output", "refined", family_name)
    os.makedirs(output_root, exist_ok=True)

    for category, syscall_set in CATEGORIES.items():
        frequency_rows = []

        print(f"\n📌 Category: {category}")

        for root, _, files in os.walk(trace_dir):
            for file in files:
                if not file.endswith("_syscalls.json"):
                    continue

                filepath = os.path.join(root, file)
                apk_folder = os.path.basename(root) if nested else os.path.splitext(file)[0]

                syscall_counts = dict.fromkeys(syscall_set, 0)
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
                    print(f"❌ Error reading {filepath}: {e}")

        if frequency_rows:
            df = pd.DataFrame(frequency_rows)
            df.set_index("APK", inplace=True)

            output_file = os.path.join(
                output_root,
                f"{family_name}_{category}_frequency_matrix.csv"
            )
            df.to_csv(output_file)
            print(f"✅ Saved Matrix → {output_file}")
        else:
            print(f"⚠ No syscalls found for: {category}")


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
