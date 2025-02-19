// tide_memory.c - Memory mapping implementation for Tide protocol
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TPU_MEM_START 0x7f4d00000000ULL
#define TPU_MEM_END   0x7f4d3b9aca00ULL
#define PAGE_SIZE     4096

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PAGE_SIZE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_MMAPABLE);
} tide_mem_map SEC(".maps");

static __always_inline int validate_access(u64 addr, u32 size)
{
    if (addr < TPU_MEM_START || addr + size > TPU_MEM_END)
        return 0;
        
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (pid_tgid >> 32 != 1234)
        return 0;
        
    return 1;
}

SEC("kprobe/tide_mem_access")
int handle_mem_access(struct pt_regs *ctx)
{
    u64 addr = PT_REGS_PARM1(ctx);
    u32 size = PT_REGS_PARM2(ctx);
    
    if (!validate_access(addr, size))
        return 0;
        
    u32 page_idx = (addr - TPU_MEM_START) / PAGE_SIZE;
    u32 page_off = (addr - TPU_MEM_START) % PAGE_SIZE;
    
    void *page = bpf_map_lookup_elem(&tide_mem_map, &page_idx);
    if (!page)
        return 0;
        
    long ret = bpf_probe_read_kernel(page + page_off, size, (void *)addr);
    if (ret < 0)
        return 0;
        
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tide_notify_map SEC(".maps");

SEC("kprobe/tide_mem_update")
int handle_mem_update(struct pt_regs *ctx)
{
    u64 *event = bpf_ringbuf_reserve(&tide_notify_map, sizeof(u64), 0);
    if (!event)
        return 0;
        
    *event = bpf_ktime_get_ns();
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
