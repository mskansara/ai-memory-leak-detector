from bcc import BPF
import sys

bpf_source = """
#include <uapi/linux/ptrace.h>

int trace_malloc(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid != TARGET_PID) {
        return 0;
    } 
    bpf_trace_printk("Malloc called: %u bytes\\n", size);
    return 0;
}

"""

if len(sys.argv) < 2:
    print("Usage: sudo python3 sniffer.py [PID_OF_TARGET_APP]")
    exit()

target_pid = sys.argv[1]

bpf_source = bpf_source.replace("TARGET_PID", target_pid)

b = BPF(text=bpf_source)

b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc")

print(f"Monitoring PID {target_pid}....Press Ctrl+C to stop.")

try:
    b.trace_print()
except KeyboardInterrupt:
    exit()
