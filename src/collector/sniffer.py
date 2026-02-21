from bcc import BPF  # type: ignore
import sys
import time
import pandas as pd  # type: ignore


bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_HASH(stack_counts, int, u64);
BPF_STACK_TRACE(stack_traces, 1024);

int trace_malloc_entry(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if(pid != TARGET_PID) return 0;

    int stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    if (stack_id < 0) return 0;

    u64 initial_val = 1;

    u64 *count = stack_counts.lookup(&stack_id);

    if(count) {
        (*count)++;
    } else {
        stack_counts.update(&stack_id, &initial_val);
    }
    return 0;
}



"""

if len(sys.argv) < 2:
    print("Usage: sudo python3 sniffer.py [PID_OF_TARGET_APP]")
    exit()

target_pid = sys.argv[1]

bpf_source = bpf_source.replace("TARGET_PID", target_pid)

b = BPF(text=bpf_source)

try:
    b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc_entry")

except Exception as e:
    print(f"Note: uretprobe failed ({e}). Switching to entry-only tracking mode.")


print(f"Tracking leaks for PID {target_pid}....Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(5)
        print("--- Memory Allocation Trends (Potential Leaks) ---")

        counts = b["stack_counts"]

        for stack_id, count in sorted(
            counts.items(), key=lambda x: x[1].value, reverse=True
        ):
            print(
                f"Function path called Malloc: {count.value} times."
            )  # This is the count value

            stack = b["stack_traces"].walk(stack_id.value)

            # This is the stack_id
            path_string = ";".join(
                [b.sym(a, int(target_pid)).decode("utf-8", "replace") for a in stack]
            )  # This is the symbol_path
            print(path_string)
            data_to_be_saved_in_csv = [
                [time.time(), stack_id.value, count.value, path_string]
            ]
            df = pd.DataFrame(data_to_be_saved_in_csv)
            df.to_csv(
                "./data/memory_telemetry.csv",
                mode="a",
                index=False,
                header=False,
                sep=",",
            )


except KeyboardInterrupt:
    print("\\Detatching...")
    exit()
