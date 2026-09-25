// SPDX-License-Identifier: MIT OR GPL-2.0
/*
 * iotap's eBPF program for Linux. For each process in `traced` it writes a record to the ring
 * buffer `records` when a call iotap traces returns, with the call's entry and return paired
 * here, and one when the process's last thread exits. When iotap follows child processes, a
 * process a traced one starts is traced from its start, with a record that says so. The record
 * layout is the one `trace::linux::Record` reads; change the two together.
 *
 * The program is self-contained: it declares the few kernel definitions it uses instead of
 * including kernel or libbpf headers, so building it takes only clang.
 */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;

#define __always_inline inline __attribute__((always_inline))
#define SEC(name) __attribute__((section(name), used))
/* How libbpf reads map definitions from BTF. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#define BPF_ANY 0
/* bpf_ringbuf_output flags, and what bpf_ringbuf_query reports. */
#define BPF_RB_NO_WAKEUP 1
#define BPF_RB_FORCE_WAKEUP 2
#define BPF_RB_AVAIL_DATA 0
#define BPF_RB_RING_SIZE 1

/* Helpers, by the numbers the kernel gives them. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				   __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;
static __u64 (*bpf_ringbuf_query)(void *ringbuf, __u64 flags) = (void *)134;

/*
 * What `calls` holds for a call iotap traces, as `trace::linux::codes::Capture::flags` writes
 * it: bit 0 traces the call, and each 4-bit field above holds an argument index plus one, or 0.
 */
#define TRACE 1u
#define PATH_ARG(flags) (((flags) >> 4) & 0xf)
#define ADDR_ARG(flags) (((flags) >> 8) & 0xf)
#define ADDR_LEN_ARG(flags) (((flags) >> 12) & 0xf)
#define FDS_ARG(flags) (((flags) >> 16) & 0xf)

#define KIND_CALL 1
#define KIND_EXIT 2
#define KIND_FORK 5

/* The clone flag that makes a thread of the caller's process rather than a process. */
#define CLONE_THREAD 0x00010000

#define MEMORY_NOTHING 0
#define MEMORY_PATH 1
#define MEMORY_SOCKADDR 2
#define MEMORY_FDS 3

/* A path of PATH_MAX bytes, terminator included, and a `struct sockaddr_storage`. */
#define MEMORY_MAX 4096
#define SOCKADDR_MAX 128

/*
 * The syscall programs attach to the raw tracepoints, which cost each syscall of every process
 * far less than the tracepoints that lay out a record first. They are passed the registers, a
 * `struct pt_regs`, and the call's number on entry or its result on return, so the program reads
 * the arguments and, on return, the number from the registers, where the kernel's headers for
 * each architecture keep them. build.rs names the architecture.
 */
#if defined(__TARGET_ARCH_x86)
/* rdi, rsi, rdx, r10, r8 and r9, among the 64-bit words from r10 (at 56) to orig_rax. */
#define REGS_AT 56
#define REGS_WORDS 9
#define ARG0 7
#define ARG1 6
#define ARG2 5
#define ARG3 0
#define ARG4 2
#define ARG5 1
/* orig_rax, whose low 32 bits hold the number. */
#define NR_AT 120
#elif defined(__TARGET_ARCH_arm64)
/* x0 to x5, the first six words; x0 still holds the first argument when the call enters. */
#define REGS_AT 0
#define REGS_WORDS 6
#define ARG0 0
#define ARG1 1
#define ARG2 2
#define ARG3 3
#define ARG4 4
#define ARG5 5
/* syscallno, 32 bits after orig_x0. */
#define NR_AT 280
#else
#error "no register layout for this architecture; build.rs defines __TARGET_ARCH_x86 or _arm64"
#endif

/* The loader attaches `process_exit` only where the tracepoint has `group_dead` here. */
struct sched_process_exit_args {
	__u64 common;
	char comm[16];
	__s32 pid;
	__s32 prio;
	__u8 group_dead;
};

/* The loader attaches `task_newtask` only where the tracepoint lays out `pid` and `clone_flags`
 * as here: `clone_flags` is an `unsigned long` in older kernels and a `u64` in newer ones, the
 * same eight bytes on the systems iotap supports. */
struct task_newtask_args {
	__u64 common;
	__s32 pid;
	char comm[16];
	__u64 clone_flags;
};

/* A call under way. */
struct call {
	__u64 ts;
	__u64 args[6];
	__u32 nr;
	__u32 pad;
};

struct record {
	/* When the call returned or the process exited. */
	__u64 ts;
	/* When the call entered the kernel; 0 when that was not seen. */
	__u64 start_ns;
	__u64 args[6];
	__s64 ret;
	__u32 pid;
	__u32 tid;
	__u32 nr;
	__u16 kind;
	__u16 memory_len;
	__u8 memory_kind;
	__u8 pad[3];
	/* Records the ring buffer had no room for before this one, wrapping at 2^32. */
	__u32 dropped;
	__u8 memory[MEMORY_MAX];
};

#define HEADER __builtin_offsetof(struct record, memory)
_Static_assert(HEADER == 96, "trace::linux::HEADER");

/* Processes to trace, by thread group id. The reader adds them, and this program adds the
 * processes they start when iotap follows child processes; this program removes one when its
 * last thread exits, and the reader when it finds one gone. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u8);
} traced SEC(".maps");

/* What to do for each call number; see TRACE. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u32);
} calls SEC(".maps");

/* Calls of traced processes under way, by thread. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct call);
} inflight SEC(".maps");

/* What the reader reads; the loader sets its size. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} records SEC(".maps");

/* Where a record is put together: it is too large for the stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct record);
} scratch SEC(".maps");

/* Records the ring buffer had no room for. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

/* Set by the reader before it detaches the programs: from then on no call starts to be traced,
 * and a return whose entry was not seen is no call under way when tracing began. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} stopping SEC(".maps");

/* The flags of call `nr` if the current process is traced and iotap traces the call. */
static __always_inline __u32 traced_call(__u32 tgid, __u32 nr)
{
	/* The call first: most calls are of kinds iotap does not trace, and looking one up in the
	 * array costs less than looking the process up in the hash map. */
	__u32 *flags = bpf_map_lookup_elem(&calls, &nr);
	if (!flags || !(*flags & TRACE))
		return 0;
	return bpf_map_lookup_elem(&traced, &tgid) ? *flags : 0;
}

static __always_inline int is_stopping(void)
{
	__u32 zero = 0;
	__u32 *flag = bpf_map_lookup_elem(&stopping, &zero);
	return flag && *flag;
}

/* Reads what the call's flags ask for from the caller's memory, as the call returns. */
static __always_inline void read_memory(struct record *rec, __u32 flags)
{
	__u32 path = PATH_ARG(flags), addr = ADDR_ARG(flags), len = ADDR_LEN_ARG(flags);
	__u32 fds = FDS_ARG(flags);

	if (path >= 1 && path <= 6) {
		long n = bpf_probe_read_user_str(rec->memory, MEMORY_MAX,
						 (const void *)rec->args[path - 1]);
		if (n > 0) {
			rec->memory_kind = MEMORY_PATH;
			/* Without the terminator. */
			rec->memory_len = n - 1;
		}
	} else if (addr >= 1 && addr <= 6 && len >= 1 && len <= 6) {
		__u64 size = rec->args[len - 1];
		if (size > SOCKADDR_MAX)
			size = SOCKADDR_MAX;
		if (size > 0 &&
		    !bpf_probe_read_user(rec->memory, size, (const void *)rec->args[addr - 1])) {
			rec->memory_kind = MEMORY_SOCKADDR;
			rec->memory_len = size;
		}
	} else if (fds >= 1 && fds <= 6 && rec->ret == 0) {
		/* Only a call that succeeded stored its two descriptors. */
		if (!bpf_probe_read_user(rec->memory, 8, (const void *)rec->args[fds - 1])) {
			rec->memory_kind = MEMORY_FDS;
			rec->memory_len = 8;
		}
	}
}

static __always_inline void output(struct record *rec)
{
	__u32 zero = 0;
	__u64 *lost = bpf_map_lookup_elem(&dropped, &zero);
	if (!lost)
		return;
	rec->dropped = (__u32)*lost;
	/* Wake the reader only once a quarter of the ring waits; it reads every few milliseconds
	 * anyway, and a wakeup per record would cost more than the record. */
	__u64 flags = bpf_ringbuf_query(&records, BPF_RB_AVAIL_DATA) >=
				      bpf_ringbuf_query(&records, BPF_RB_RING_SIZE) / 4 ?
			      BPF_RB_FORCE_WAKEUP :
			      BPF_RB_NO_WAKEUP;
	__u64 size = HEADER + (rec->memory_len & (MEMORY_MAX - 1));
	if (bpf_ringbuf_output(&records, rec, size, flags))
		__sync_fetch_and_add(lost, 1);
}

/* ctx[0] is the registers, ctx[1] the call's number. */
SEC("raw_tracepoint/sys_enter")
int sys_enter(__u64 *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32, tid = (__u32)id, nr = (__u32)ctx[1];
	if (!traced_call(tgid, nr) || is_stopping())
		return 0;
	__u64 regs[REGS_WORDS];
	if (bpf_probe_read_kernel(regs, sizeof(regs), (const void *)(ctx[0] + REGS_AT)))
		return 0;
	struct call call = {
		.ts = bpf_ktime_get_ns(),
		.args = {regs[ARG0], regs[ARG1], regs[ARG2], regs[ARG3], regs[ARG4], regs[ARG5]},
		.nr = nr,
	};
	bpf_map_update_elem(&inflight, &tid, &call, BPF_ANY);
	return 0;
}

/* ctx[0] is the registers, ctx[1] the call's result. */
SEC("raw_tracepoint/sys_exit")
int sys_exit(__u64 *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32, tid = (__u32)id;
	/* The process first here: the call's number takes a read of the registers. */
	if (!bpf_map_lookup_elem(&traced, &tgid))
		return 0;
	__u32 nr;
	if (bpf_probe_read_kernel(&nr, sizeof(nr), (const void *)(ctx[0] + NR_AT)))
		return 0;
	__u32 *call_flags = bpf_map_lookup_elem(&calls, &nr);
	if (!call_flags || !(*call_flags & TRACE))
		return 0;
	__u32 flags = *call_flags;
	__u32 zero = 0;
	struct record *rec = bpf_map_lookup_elem(&scratch, &zero);
	if (!rec)
		return 0;
	/* The record's place in time, taken before it is written: the reader relies on a record
	 * reaching the ring within moments of this. */
	rec->ts = bpf_ktime_get_ns();
	rec->ret = (__s64)ctx[1];
	rec->pid = tgid;
	rec->tid = tid;
	rec->nr = nr;
	rec->kind = KIND_CALL;
	rec->memory_kind = MEMORY_NOTHING;
	rec->memory_len = 0;
	struct call *call = bpf_map_lookup_elem(&inflight, &tid);
	if (call && call->nr == nr) {
		rec->start_ns = call->ts;
		for (int i = 0; i < 6; i++)
			rec->args[i] = call->args[i];
		read_memory(rec, flags);
	} else {
		if (is_stopping()) {
			if (call)
				bpf_map_delete_elem(&inflight, &tid);
			return 0;
		}
		/* It entered the kernel before tracing began. */
		rec->start_ns = 0;
		for (int i = 0; i < 6; i++)
			rec->args[i] = 0;
	}
	if (call)
		bpf_map_delete_elem(&inflight, &tid);
	output(rec);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int process_exit(struct sched_process_exit_args *ctx)
{
	if (!ctx->group_dead)
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&traced, &tgid))
		return 0;
	__u32 zero = 0;
	struct record *rec = bpf_map_lookup_elem(&scratch, &zero);
	if (!rec)
		return 0;
	rec->ts = bpf_ktime_get_ns();
	rec->start_ns = 0;
	for (int i = 0; i < 6; i++)
		rec->args[i] = 0;
	rec->ret = 0;
	rec->pid = tgid;
	rec->tid = 0;
	rec->nr = 0;
	rec->kind = KIND_EXIT;
	rec->memory_kind = MEMORY_NOTHING;
	rec->memory_len = 0;
	output(rec);
	/* A later process given the same pid is not traced. */
	bpf_map_delete_elem(&traced, &tgid);
	return 0;
}

/*
 * A task was created, in the context of the task that created it and before it can run, so a
 * child of a traced process is traced from its first call. A thread of a traced process is
 * traced with it already.
 */
SEC("tracepoint/task/task_newtask")
int task_newtask(struct task_newtask_args *ctx)
{
	if (ctx->clone_flags & CLONE_THREAD)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (!bpf_map_lookup_elem(&traced, &tgid) || is_stopping())
		return 0;
	__u32 zero = 0;
	struct record *rec = bpf_map_lookup_elem(&scratch, &zero);
	if (!rec)
		return 0;
	__u32 child = ctx->pid;
	__u8 on = 1;
	/* 0 once the child is traced; a full map refuses it. */
	rec->ret = bpf_map_update_elem(&traced, &child, &on, BPF_ANY);
	rec->ts = bpf_ktime_get_ns();
	rec->start_ns = 0;
	for (int i = 0; i < 6; i++)
		rec->args[i] = 0;
	rec->args[0] = child;
	rec->pid = tgid;
	rec->tid = (__u32)id;
	rec->nr = 0;
	rec->kind = KIND_FORK;
	rec->memory_kind = MEMORY_NOTHING;
	rec->memory_len = 0;
	output(rec);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
