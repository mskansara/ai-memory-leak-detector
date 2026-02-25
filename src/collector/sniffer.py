from bcc import BPF  # type: ignore
import time
import pandas as pd  # type: ignore


def start_sniffing(target_pid, duration, output_path):

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



    """.replace(
        "TARGET_PID", str(target_pid)
    )

    b = BPF(text=bpf_source)

    try:
        b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc_entry")

    except Exception as e:
        print(f"Note: uretprobe failed ({e}). Switching to entry-only tracking mode.")

    print(f"[*] Monitoring PID {target_pid} for {duration} seconds...")

    start_time = time.time()

    while time.time() - start_time < duration:
        time.sleep(5)
        counts = b["stack_counts"]
        batch_data = []

        for stack_id, count in counts.items():
            stack = b["stack_traces"].walk(stack_id.value)
            path_string = ";".join(
                [b.sym(a, int(target_pid)).decode("utf-8", "replace") for a in stack]
            )
            batch_data.append([time.time(), stack_id.value, count.value, path_string])

        if batch_data:
            df = pd.DataFrame(batch_data)
            df.to_csv(output_path, mode="a", index=False, header=False, sep=",")
