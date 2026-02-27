from bcc import BPF  # type: ignore
import time
import pandas as pd  # type: ignore
import os


def start_sniffing(target_pid, duration, output_path):
    print(f"[*] Verifying visibility of PID {target_pid}...")
    if not os.path.exists(f"/proc/{target_pid}"):
        print(f"❌ ERROR: PID {target_pid} is not visible to this container!")
        print("    Check if 'pid: host' is in your docker-compose.yml.")
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("")

    print(f"[*] Created telemetry file at {output_path}")

    bpf_source = """
    #include <uapi/linux/ptrace.h>
    BPF_HASH(stack_counts, int, u64);
    BPF_STACK_TRACE(stack_traces, 1024);

    int trace_alloc_entry(struct pt_regs *ctx) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if(pid != TARGET_PID) return 0;

        int stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        if (stack_id < 0) return 0;

        u64 *count = stack_counts.lookup(&stack_id);
        if(count) {
            (*count)++;
        } else {
            u64 initial_val = 1;
            stack_counts.update(&stack_id, &initial_val);
        }
        return 0;
    }
    """.replace(
        "TARGET_PID", str(target_pid)
    )

    b = BPF(text=bpf_source)
    target_libc = f"/proc/{target_pid}/root/lib/aarch64-linux-gnu/libc.so.6"
    target_stdcpp = f"/proc/{target_pid}/root/lib/aarch64-linux-gnu/libstdc++.so.6"

    try:
        b.attach_uprobe(name=target_libc, sym="malloc", fn_name="trace_alloc_entry")
        b.attach_uprobe(name=target_stdcpp, sym="_Znam", fn_name="trace_alloc_entry")
        print(f"[*] Probes locked onto {target_libc}")
    except Exception as e:
        print(f"[*] Fallback: Attempting generic 'c' and 'stdc++' library names...")
        try:
            b.attach_uprobe(name="c", sym="malloc", fn_name="trace_alloc_entry")
            b.attach_uprobe(name="stdc++", sym="_Znam", fn_name="trace_alloc_entry")
        except:
            print(f"❌ FATAL: Library not found: {e}")
            return

    print(f"[*] Monitoring PID {target_pid} for {duration} seconds...")
    start_time = time.time()

    while time.time() - start_time < duration:
        try:
            time.sleep(2)

            counts = b["stack_counts"]
            items_found = len(list(counts.items()))  # Check if the map has ANY data
            print(
                f"   [HEARTBEAT] {int(time.time() - start_time)}s | Stacks in Map: {items_found}"
            )
            batch_data = []

            for stack_id, count in counts.items():
                stack = b["stack_traces"].walk(stack_id.value)
                # Symbol resolution: this is the 'heavy' part
                syms = [
                    b.sym(a, int(target_pid)).decode("utf-8", "replace") for a in stack
                ]
                path_string = ";".join(syms)
                batch_data.append(
                    [time.time(), stack_id.value, count.value, path_string]
                )

            if batch_data:
                df = pd.DataFrame(batch_data)
                # Fix: Ensure we use a clean CSV format and force the write to disk
                df.to_csv(output_path, mode="a", index=False, header=False, sep=",")
                # Senior Tip: Print a heartbeat so we know the 'Producer' is working
                os.sync()
                print(f"[*] Flushed {len(batch_data)} telemetry rows to {output_path}")

        except KeyboardInterrupt:
            break

    print("[*] Sniffing complete.")
