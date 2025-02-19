#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

#include <linux/types.h>
#include <asm/ptrace.h>
#include <bpf/bpf_tracing.h>

#define ALLOWED_START 0x1000000
#define ALLOWED_END   0x2000000

SEC("kprobe/tide_mem_access")
int tide_mem_access(struct pt_regs *ctx)
{
    unsigned long addr = PT_REGS_PARM1(ctx);

    if (addr < ALLOWED_START || addr > ALLOWED_END) {
        bpf_printk("Tide: Blocked unauthorized access at 0x%lx\n", addr);
        return -1;
    }

    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != 1234) {
        bpf_printk("Tide: Blocked access from unauthorized process %d\n", pid);
        return -1;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
