from bcc import BPF  # type: ignore
import time
import pandas as pd  # type: ignore
import os
import platform
from prometheus_client import start_http_server, Gauge

ALLOC_GAUGE = Gauge(
    "ebpf_memory_allocations_total",
    "Total memory allocations tracked by eBPF",
    ["pid", "process_name", "stack_id", "symbol_path"],
)


def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except:
        return "unknown"


def start_sniffing(duration, output_path=None):

    print("[*] Initializing Prometheus Exporter on port 8000...")
    # 2. Start the HTTP server for Prometheus to scrape
    start_http_server(8000, addr="0.0.0.0")

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
        # Most common path in Lima/Ubuntu
        libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
        std_path = "/lib/x86_64-linux-gnu/libstdc++.so.6"

        b.attach_uprobe(name=libc_path, sym="malloc", fn_name="trace_alloc_entry")
        b.attach_uprobe(
            name=std_path, sym="_Znam", fn_name="trace_alloc_entry"
        )  # new[]
        b.attach_uprobe(name=std_path, sym="_Znwm", fn_name="trace_alloc_entry")  # new
        print(f"Probes locked onto {libc_path}")
    except:
        # Fallback to defaults if paths differ
        b.attach_uprobe(name="c", sym="malloc", fn_name="trace_alloc_entry")
        b.attach_uprobe(name="stdc++", sym="_Znam", fn_name="trace_alloc_entry")
        print(f"[*] Monitoring system-wide allocations for {duration} seconds...")
    start_time = time.time()

    while time.time() - start_time < duration:
        try:
            time.sleep(5)

            counts = b["stack_counts"]
            stack_traces = b["stack_traces"]

            for key, count in counts.items():
                pid = key.pid
                stack_id = key.stack_id
                proc_name = get_process_name(pid)
                stack = stack_traces.walk(stack_id)

                syms = []
                for addr in stack:
                    sym = b.sym(addr, pid).decode("utf-8", "replace")
                    syms.append(sym)

                path_string = ";".join(syms)

                ALLOC_GAUGE.labels(
                    pid=pid,
                    process_name=proc_name,
                    stack_id=stack_id,
                    symbol_path=path_string,
                ).set(count.value)
            print(
                f"   [PROMETHEUS] Heartbeat: Metrics updated for {len(counts)} paths."
            )

        except KeyboardInterrupt:
            break

    print("[*] Sniffing complete.")
