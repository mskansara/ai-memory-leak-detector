from bcc import BPF  # type: ignore
import time
import pandas as pd  # type: ignore
import os
import platform


def start_sniffing(duration, output_path):

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("timestamp,pid,stack_id,alloc_count,symbol_path\n")

    print(f"[*] Global Watcher initialized. Telemetry: {output_path}")

    bpf_source = """
    #include <uapi/linux/ptrace.h>

    struct key_t {
        u32 pid;
        int stack_id;
    };
    BPF_HASH(stack_counts, struct key_t, u64);
    BPF_STACK_TRACE(stack_traces, 1024);

    int trace_alloc_entry(struct pt_regs *ctx) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        
        u32 self_pid = SELF_PID_FILTER;
        if(pid == self_pid) return 0;

        struct key_t key = {};
        key.pid = pid;
        key.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        if (key.stack_id < 0) return 0;

        u64 *count = stack_counts.lookup(&key);
        if(count) {
            (*count)++;
        } else {
            u64 initial_val = 1;
            stack_counts.update(&key, &initial_val);
        }
        return 0;
    }
    """
    self_pid = os.getpid()
    bpf_source = bpf_source.replace("SELF_PID_FILTER", str(self_pid))
    b = BPF(text=bpf_source)

    arch = platform.machine()
    lib_prefix = (
        "/usr/lib/x86_64-linux-gnu"
        if arch == "x86_64"
        else "/usr/lib/aarch64-linux-gnu"
    )
    libc_path = f"{lib_prefix}/libc.so.6"
    stdcpp_path = f"{lib_prefix}/libstdc++.so.6"

    try:
        b.attach_uprobe(name="c", sym="malloc", fn_name="trace_alloc_entry")
        b.attach_uprobe(name="stdc++", sym="_Znwm", fn_name="trace_alloc_entry")  # new
        b.attach_uprobe(name="stdc++", sym="_Znam", fn_name="trace_alloc_entry")
        print(f"[*] Global Probes locked onto libc and libstdc++")
    except Exception as e:
        print(f"❌ FATAL: Could not attach global probes: {e}")
        return
    print(f"[*] Monitoring system-wide allocations for {duration} seconds...")
    start_time = time.time()
    start_time = time.time()

    while time.time() - start_time < duration:
        try:
            time.sleep(5)

            counts = b["stack_counts"]
            stack_traces = b["stack_traces"]
            batch_data = []
            current_ts = time.time()

            for key, count in counts.items():
                pid = key.pid
                stack_id = key.stack_id

                stack = stack_traces.walk(stack_id)

                syms = []
                for addr in stack:
                    sym = b.sym(addr, pid).decode("utf-8", "replace")
                    syms.append(sym)

                path_string = ";".join(syms)

                batch_data.append([current_ts, pid, stack_id, count.value, path_string])

            if batch_data:
                df = pd.DataFrame(
                    batch_data
                )  # Fix: Ensure we use a clean CSV format and force the write to disk
                df.to_csv(output_path, mode="a", index=False, header=False, sep=",")
                os.sync()
                print(
                    f"   [HEARTBEAT] {int(time.time() - start_time)}s | Tracked {len(batch_data)} active allocation paths across system."
                )

        except KeyboardInterrupt:
            break

    print("[*] Sniffing complete.")
