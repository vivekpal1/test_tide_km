obj-m += tide_kernel_module.o
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
CLANG ?= clang
LLC ?= llc

all: ebpf_probe.o tide_kernel_module.ko

tide_kernel_module.ko: tide_kernel_module.c
	make -C $(KERNEL_DIR) M=$(PWD) modules

ebpf_probe.o: ebpf_probe.c
	$(CLANG) -target bpf -O2 -Wall -c $< -o $@

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f ebpf_probe.o

load:
	sudo insmod tide_kernel_module.ko

unload:
	sudo rmmod tide_kernel_module
