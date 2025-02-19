#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ptrace.h>

#define MODULE_NAME "tide_kmod"
#define ALLOWED_START 0x7f4d00000000  // TPU buffer base address
#define ALLOWED_END   0x7f4d3b9aca00  // TPU buffer end address

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vivek");
MODULE_DESCRIPTION("Tide Kernel Module for Safe Validator Memory Access");

static struct bpf_prog *ebpf_prog = NULL;
static int major_num;

/* eBPF Program */
struct bpf_insn ebpf_code[] = {
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, offsetof(struct pt_regs, di)),
    BPF_JMP_IMM(BPF_JGE, BPF_REG_7, ALLOWED_START, 2),
    BPF_JMP_IMM(BPF_JGT, ALLOWED_END, BPF_REG_7, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_IMM(BPF_REG_0, 1),
    BPF_EXIT_INSN(),
};

static struct bpf_prog_load_attr ebpf_attr = {
    .prog_type = BPF_PROG_TYPE_KPROBE,
    .insns = ebpf_code,
    .license = "GPL",
    .insn_cnt = ARRAY_SIZE(ebpf_code),
};

static int tide_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long size = vma->vm_end - vma->vm_start;
    
    if (offset < ALLOWED_START || (offset + size) > ALLOWED_END) {
        pr_err("Tide: Invalid memory access attempt\n");
        return -EACCES;
    }

    if (remap_pfn_range(vma, vma->vm_start,
                       (ALLOWED_START >> PAGE_SHIFT) + vma->vm_pgoff,
                       size, vma->vm_page_prot)) {
        return -EAGAIN;
    }

    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .mmap = tide_mmap,
};

static int __init tide_init(void)
{
    // Load eBPF program
    ebpf_prog = bpf_prog_load_xattr(&ebpf_attr, NULL, NULL);
    if (IS_ERR(ebpf_prog)) {
        pr_err("Tide: Failed to load eBPF program\n");
        return PTR_ERR(ebpf_prog);
    }

    // Register character device
    major_num = register_chrdev(0, MODULE_NAME, &fops);
    if (major_num < 0) {
        pr_err("Tide: Failed to register device\n");
        bpf_prog_put(ebpf_prog);
        return major_num;
    }

    pr_info("Tide: Module loaded (major=%d)\n", major_num);
    return 0;
}

static void __exit tide_exit(void)
{
    unregister_chrdev(major_num, MODULE_NAME);
    if (ebpf_prog) bpf_prog_put(ebpf_prog);
    pr_info("Tide: Module unloaded\n");
}

module_init(tide_init);
module_exit(tide_exit);
