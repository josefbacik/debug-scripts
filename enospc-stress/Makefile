CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CFLAGS := -Wall -Werror -D_GNU_SOURCE
LIBS := -lpthread -lelf -lz
LIBBPF_OBJ := /usr/lib64/libbpf.a

all: enospc-stress

# Generate vmlinux.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build the bpf code itself
%.bpf.o: vmlinux.h %.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

# Generate the skel file
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skel $< > $@

# This doesnt' work and I don't fucking know why
#%.o: %.c %.skel.h common.h
#	$(CC) $(CFLAGS) -c enospc-stress.c -o $@

#%: %.o
#	$(CC) $(CFLAGS) $^ $(LIBBPF_OBJ) $(LIBS) -o $@

enospc-stress.o: enospc-stress.c enospc-stress.skel.h common.h
	$(CC) $(CFLAGS) -c enospc-stress.c -o $@

enospc-stress: enospc-stress.o
	$(CC) $(CFLAGS) $^ $(LIBBPF_OBJ) $(LIBS) -o $@
