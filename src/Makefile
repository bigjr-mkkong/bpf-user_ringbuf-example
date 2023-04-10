BPFTOOL = bpftool
CC = clang
BPF_FLAGS = -g -Og -target bpf -D__TARGET_ARCH_x86_64 -c
CFLAGS = -g -O2 -Wall -I . -c 
LD_FLAGS = -Wall -O2 -g -lelf -lz

LIBBPF=/usr/lib/libbpf.so

BINARY=user_ringbuf

all: $(BINARY)

vmlinux.h:/sys/kernel/btf/vmlinux
	$(BPFTOOL) btf dump file $^ format c > $@

user_ringbuf.bpf.o:user_ringbuf.bpf.c vmlinux.h
	$(CC) $(BPF_FLAGS) -o $@ user_ringbuf.bpf.c

user_ringbuf.skel.h:user_ringbuf.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

user_ringbuf.o:user_ringbuf.c user_ringbuf.skel.h
	$(CC) $(CFLAGS) -o $@ user_ringbuf.c

$(BINARY): user_ringbuf.o $(LIBBPF)
	$(CC) $(LD_FLAGS) $^ -o $@

clean:
	rm $(BINARY) *.o *.h *.i
