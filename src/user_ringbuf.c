#include "stdio.h"
#include "fcntl.h"
#include "unistd.h"
#include "bpf/libbpf.h"
#include "bpf/bpf.h"
#include <sys/resource.h>
#include <sys/syscall.h>
#include "error.h"

#include "user_ringbuf.skel.h"

#define u64 uint64_t
#define u32 uint32_t


int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	
	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
	
	close(trace_fd);
}

void read_1line_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	
	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
            goto end;
		}
	}
end:
	close(trace_fd);
}

int main(void){
    struct user_ringbuf_bpf *obj;
	struct user_ring_buffer *uring = NULL;
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    bump_memlock_rlimit();

	/* Load and verify BPF application */
	obj = user_ringbuf_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = user_ringbuf_bpf__load(obj);
	if(err){
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint */
	err = user_ringbuf_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return 1;
	}


    printf("Program attached\n");

	uring = user_ring_buffer__new(bpf_map__fd(obj->maps.uring), NULL);
	if (libbpf_get_error(uring)) {
		err = -1;
		fprintf(stderr, "Failed to create user ring buffer\n");
		return 1;
	}

	int user_magic[] = {0xdeadbeef, 0xbadc0de, 0xdeadface}, send_pt = 0;

	int sample_number = 0;
    int *msg = NULL;
    while(1){
        msg = user_ring_buffer__reserve(uring, sizeof(int));
        if(!msg){
            printf("Failed to reserve a position in uring: %s", strerror(errno));
            //sleep(1000);
        }else{
            *msg = user_magic[send_pt % 3];
            send_pt++;
            user_ring_buffer__submit(uring, msg);
        }
        read_1line_trace_pipe();    
    }

    return 0;
}
