from bcc import BPF  # type: ignore
import sys
import time

bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_HASH(allocations, u64, u64);

int trace_malloc_exit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != TARGET_PID) {
        return 0;
    } 

    u64 addr = PT_REGS_RC(ctx);
    u64 size = 1024;

    if(addr != 0) {
        allocations.update(&addr, &size);
    }
    return 0;
}

int trace_free_entry(struct pt_regs *ctx, void *addr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != TARGET_PID) {
        return 0;
    }

    u64 address = (u64)addr;
    allocations.delete(&address);
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
        time.sleep(2)
        print("--- Active Memory Blocks (Potential Leaks) ---")
        count = 0
        for addr, size in b["allocations"].items():
            count += 1
            print(f"Leaked Address: {hex(addr.value)} | Size: {size.value} bytes")

        if count == 0:
            print("No leaks detected yet. Everything is being freed.")
        print(f"Total outstanding Blocks: {count}")

except KeyboardInterrupt:
    print("\\Detatching...")
    exit()
