#!/bin/bash
# Load module
sudo insmod tide_kernel_module.ko

# Create device node
major=$(grep tide /proc/devices | awk '{print $1}')
sudo mknod /dev/tide c $major 0
sudo chmod 666 /dev/tide

# Test memory access
dd if=/dev/tide bs=4096 count=1 of=/tmp/tide_test

# Cleanup
sudo rm /dev/tide
sudo rmmod tide_kernel_module
