# eBPF Program Compilation Makefile
CLANG ?= clang
LLC ?= llc
ARCH ?= $(subst x86_64,x86,$(shell uname -m))
KDIR ?= /lib/modules/$(shell uname -r)/build
BPF_TARGET = bpf
BIN = tide_kern.o

# Architecture-specific flags
CLANG_ARCH_FLAGS := -D__TARGET_ARCH_$(ARCH)
CLANG_FLAGS = -g -O2 -Wall -Werror \
    -target $(BPF_TARGET) \
    -nostdinc \
    -I$(KDIR)/arch/$(ARCH)/include \
    -I$(KDIR)/arch/$(ARCH)/include/generated \
    -I$(KDIR)/include \
    -I$(KDIR)/arch/$(ARCH)/include/uapi \
    -I$(KDIR)/include/uapi \
    -I$(KDIR)/include/generated/uapi \
    -I./include \
    -include $(KDIR)/include/linux/kconfig.h \
    -D__KERNEL__ \
    -D__BPF_TRACING__ \
    $(CLANG_ARCH_FLAGS) \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member \
    -Wno-tautological-compare \
    -Wno-unknown-warning-option

all: $(BIN)

# Compile multiple eBPF C files into single object
$(BIN): ebpf_probe.c tide_memory.c
	$(CLANG) $(CLANG_FLAGS) -c $^ -o combined.bc
	$(LLC) -march=bpf -mcpu=probe -filetype=obj -o $@ combined.bc
	rm -f combined.bc

clean:
	rm -f $(BIN) *.bc

# Helper targets
debug:
	$(CLANG) -S $(CLANG_FLAGS) -c ebpf_probe.c -o - | llvm-mca

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: all clean debug vmlinux
