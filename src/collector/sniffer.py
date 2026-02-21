from bcc import BPF  # type: ignore
import sys
import time

bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_HASH(alloc_stacks, u64, int);

BPF_STACK_TRACE(stack_traces, 1024);

int trace_malloc_exit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != TARGET_PID) return 0;

    u64 addr = PT_REGS_RC(ctx);

    if (addr == 0) return 0;

    int stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    alloc_stacks.update(&addr, &stack_id);

    return 0;

}

int trace_free_entry(struct pt_regs *ctx, void *addr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;

    u64 address = (u64)addr;
    alloc_stacks.delete(&address);
    return 0;
}
"""

if len(sys.argv) < 2:
    print("Usage: sudo python3 sniffer.py [PID_OF_TARGET_APP]")
    exit()

target_pid = sys.argv[1]

bpf_source = bpf_source.replace("TARGET_PID", target_pid)

b = BPF(text=bpf_source)

b.attach_uretprobe(name="c", sym="malloc", fn_name="trace_malloc_exit")

b.attach_uprobe(name="c", sym="free", fn_name="trace_free_entry")

print(f"Tracking leaks for PID {target_pid}....Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(5)
        print("--- Active Memory Blocks (Potential Leaks) ---")

        for addr, stack_id in b["alloc_stacks"].items():

            print(f"Leaked Address: {hex(addr.value)}")
            stack = b["stack_traces"].walk(stack_id.value)
            for addr_in_stack in stack:
                print(
                    f"  -> {b.sym(addr_in_stack, int(target_pid)).decode('utf-8', 'replace')}"
                )


except KeyboardInterrupt:
    print("\\Detatching...")
    exit()
