#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define u64 uint64_t
#define u32 uint32_t

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
    __uint(max_entries, 1 * 4096);
} uring SEC(".maps");

static long uring_handler(struct bpf_dynptr *dynptr, void *ctx){
    int *magic_number = bpf_dynptr_data(dynptr, 0, sizeof(int));
    if(!magic_number){
        bpf_printk("Failed to get magic number");
        return 1;
    }

    bpf_printk("Userspace magic number: 0x%x\n", *magic_number);

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_execve")

int bpf_prog(void *ctx){
    int err = bpf_user_ringbuf_drain(&uring, uring_handler, NULL, 0);
    if(err < 0){
        bpf_printk("bpf_user_ringbuf_drain() failed, returned: %d\n", err);
    }else if(err == 0){
        bpf_printk("bpf_user_ringbuf_drain(): no sample in ringbuffer\n");
    }else{
        bpf_printk("bpf_user_ringbuf_drain(): drained %d samples in this ringbuffer\n", err);
    }

    return err;
}

char LICENSE[] SEC("license") = "GPL";
