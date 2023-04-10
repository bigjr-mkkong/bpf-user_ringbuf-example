# Example of how to use BPF_MAY_TYPE_USER_RINGBUF

`BPF_MAP_TYPE_USER_RINGBUF` has been introduced in this [commit](https://lwn.net/Articles/908796/), but there aren't many examples except the one in [Linux kernel](https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/progs/user_ringbuf_success.c) This repo gives a simple example of how to use `BPF_MAP_TYPE_USER_RINGBUF`.

Loader will load & attach a bpf program into the kernel(at tracepoint/syscalls/sys_enter_execve) and send some userspace magic number to attached bpf program using BPF_MAP_TYPE_USER_RINGBUF.

the result should looks like:
```

bpf_trace_printk: Userspace magic number: 0xdeadbeef

bpf_trace_printk: bpf_user_ringbuf_drain(): drained 1 samples in this ringbuffer


bpf_trace_printk: Userspace magic number: 0xbadc0de

bpf_trace_printk: bpf_user_ringbuf_drain(): drained 1 samples in this ringbuffer


bpf_trace_printk: Userspace magic number: 0xdeadface

bpf_trace_printk: bpf_user_ringbuf_drain(): drained 1 samples in this ringbuffer

```

# Building

First make sure kernel has been configured with `CONFIG_DEBUG_INFO_BTF=y`, then clone the repo and cd into `src/` and use

```
make LIBBPF=<path of libbpf> 
```
to compile both bpf program and its loader.

Then, use 
```
sudo ./user_ringbuf
```
to load the bpf program into the kernel. After that, just open some process(browser, command line, etc.) and await bpf program printout the magic number send by usersite loader.

Here is a step-by-step build command for this project:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -Og -target bpf -D__TARGET_ARCH_x86_64 -c user_ringbuf.bpf.c -o user_ringbuf.bpf.o
bpftool gen skeleton user_ringbuf.bpf.o > user_ringbuf.skel.h
clang -g -O2 -Wall -I . -c user_ringbuf.c -o user_ringbuf.o
clang -Wall -O2 -g -lelf -lz user_ringbuf.o /usr/lib/libbpf.a -o user_ringbuf
sudo ./user_ringbuf
```