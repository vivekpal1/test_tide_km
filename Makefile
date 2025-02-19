# eBPF Build System for Tide Protocol
CLANG ?= clang
LLC ?= llc
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')
KDIR ?= /lib/modules/$(shell uname -r)/build
BPF_TARGET = bpf
BIN = tide_kern.o

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

SRCS = ebpf_probe.c tide_memory.c
OBJS = $(SRCS:.c=.o)
BCS = $(SRCS:.c=.bc)

all: $(BIN)

%.bc: %.c
	$(CLANG) $(CLANG_FLAGS) -emit-llvm -c $< -o $@

combined.bc: $(BCS)
	llvm-link $^ -o $@

$(BIN): combined.bc
	$(LLC) -march=bpf -mcpu=probe -filetype=obj -o $@ $<

clean:
	rm -f $(BIN) $(OBJS) $(BCS) *.bc

debug:
	$(CLANG) -S $(CLANG_FLAGS) -c ebpf_probe.c -o - | llvm-mca

.PHONY: all clean debug
