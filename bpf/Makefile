# BPF 程序编译 Makefile

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

# 编译选项
CFLAGS := -O2 -g -target bpf
CFLAGS += -D__TARGET_ARCH_x86_64
CFLAGS += -Wall -Werror

# 内核头文件路径
KERNEL_HEADERS := /usr/include
BPF_HEADERS := /usr/include/bpf

# 目标文件
TARGET := xdp_dns_filter

.PHONY: all clean vmlinux

all: $(TARGET)_bpfel.o $(TARGET)_bpfeb.o

# 生成 vmlinux.h (如果需要)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 编译小端 BPF 程序
$(TARGET)_bpfel.o: $(TARGET).c $(TARGET).h
	$(CLANG) $(CFLAGS) \
		-I$(KERNEL_HEADERS) \
		-I$(BPF_HEADERS) \
		-I. \
		-c $< \
		-o $@

# 编译大端 BPF 程序
$(TARGET)_bpfeb.o: $(TARGET).c $(TARGET).h
	$(CLANG) $(CFLAGS) \
		-I$(KERNEL_HEADERS) \
		-I$(BPF_HEADERS) \
		-I. \
		-mbig-endian \
		-c $< \
		-o $@

clean:
	rm -f *.o vmlinux.h

# 检查 BPF 程序
check: $(TARGET)_bpfel.o
	$(BPFTOOL) prog load $< /sys/fs/bpf/$(TARGET) || true
	$(BPFTOOL) prog show name xdp_dns_filter || true
	rm -f /sys/fs/bpf/$(TARGET) || true

