from bcc import BPF
import ctypes as ct

b = BPF(text="""
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

#define OP_NAME_LEN 32

typedef struct sock_data_s {
	u64 pid;
	u64 port;
	u64 bytes;
	u64 time;
	char opname[OP_NAME_LEN];
} sock_data_t;

BPF_HASH(holders, struct socket *);
BPF_HASH(files, struct file *);
BPF_HASH(pids, u64);
BPF_PERF_OUTPUT(sends);
BPF_PERF_OUTPUT(accepts);
BPF_HASH(stack_hash, u64);
BPF_HASH(ops, u64, sock_data_t);
BPF_STACK_TRACE(stack_traces, 1024);

int trace_inet_stream_connect(struct pt_regs *ctx, struct socket *socket,
				struct sockaddr *uaddr)
{
	struct sockaddr_in *saddr = (struct sockaddr_in *)uaddr;
	u16 port = saddr->sin_port;
	port = ntohs(port);

	if (port == 0xcea) {
		u64 tmp = 12345;
		holders.update(&socket, &tmp);
		sock_data_t data = {
			.pid = bpf_get_current_pid_tgid(),
			.port = port,
			.bytes = 0,
			.time = bpf_ktime_get_ns(),
			.opname = "connect",
		};
		sends.perf_submit(ctx, &data, sizeof(data));
	}
	return 0;
}

int trace_sk_filter(struct pt_regs *ctx, struct sock *sk)
{
	struct socket *socket = sk->sk_socket;
	u64 *tmp;

	tmp = holders.lookup(&socket);
	if (!tmp)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	u64 blah = 12345;
	pids.update(&pid, &blah);
	return 0;
}

int trace_sk_filter_ret(struct pt_regs *ctx)
{
	u64 *tmp;
	u64 ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	tmp = pids.lookup(&pid);
	if (!tmp)
		return 0;
	sock_data_t data = {
		.pid = pid,
		.port = 0,
		.bytes = ret,
		.time = bpf_ktime_get_ns(),
		.opname = "FUCKED",
	};
	sends.perf_submit(ctx, &data, sizeof(data));
	pids.delete(&pid);
	return 0;
}

int trace_inet_accept(struct pt_regs *ctx, struct socket *socket,
		      struct socket *newsock)
{
	struct file *file = newsock->file;
	u16 port = socket->sk->__sk_common.skc_num;
	u16 newport = newsock->sk->__sk_common.skc_dport;

	if (port == 0xcea) {
		u64 tmp = 12345;
		u64 pid = bpf_get_current_pid_tgid();
		holders.update(&newsock, &tmp);
		holders.update(&socket, &tmp);
		files.update(&file, &tmp);
//		pids.update(&pid, &tmp);
		sock_data_t data = {
			.pid = pid,
			.port = newport,
			.bytes = 0,
			.time = bpf_ktime_get_ns(),
			.opname = "accept",
		};
		sends.perf_submit(ctx, &data, sizeof(data));
//		accepts.perf_submit(ctx, &pid, sizeof(pid));
	}
	return 0;
}

int trace_sock_sendmsg(struct pt_regs *ctx, struct socket *socket)
{
	u64 blah = 12345;
	u64 *tmp;
	u16 port = socket->sk->__sk_common.skc_dport;

	tmp = holders.lookup(&socket);
	if (!tmp)
		return 0;
	sock_data_t data = {
		.pid = bpf_get_current_pid_tgid(),
		.port = port,
		.opname = "sendmsg",
	};
//	pids.update(&data.pid, &blah);
	ops.update(&data.pid, &data);
	return 0;
}

int trace_sock_recvmsg(struct pt_regs *ctx, struct socket *socket)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 *tmp, *blah;
	u16 port = socket->sk->__sk_common.skc_dport;

/*	
	blah = pids.lookup(&pid);
	if (!blah)
		return 0;

	accepts.perf_submit(ctx, &pid, sizeof(pid));
*/
	tmp = holders.lookup(&socket);
	if (!tmp)
		return 0;

	sock_data_t data = {
		.pid = bpf_get_current_pid_tgid(),
		.port = port,
		.opname = "recvmsg",
	};
	ops.update(&data.pid, &data);
	return 0;
}

int trace_sock_op_ret(struct pt_regs *ctx)
{
	u64 bytes = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	sock_data_t *data;
	
	data = ops.lookup(&pid);
	if (!data)
		return 0;
	data->bytes = bytes;
	data->time = bpf_ktime_get_ns();
	sends.perf_submit(ctx, data, sizeof(sock_data_t));
	ops.delete(&pid);
	return 0;
}

int trace_sock_op_ret_recv(struct pt_regs *ctx)
{
	u64 bytes = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	sock_data_t *data;
	
	data = ops.lookup(&pid);
	if (!data)
		return 0;
	data->bytes = bytes;
	data->time = bpf_ktime_get_ns();
	sends.perf_submit(ctx, data, sizeof(sock_data_t));
	ops.delete(&pid);
	return 0;
}
/*
int trace_sk_method(struct pt_regs *ctx, struct sock *sk)
{
	u64 *tmp;

	tmp = holders.lookup(&sk);
	if (!tmp)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	sends.perf_submit(ctx, &pid, sizeof(pid));
	holders.delete(&sk);
	return 0;
}
int trace_fdget(struct pt_regs *ctx)
{
	unsigned long v = (unsigned long)PT_REGS_RC(ctx);
	struct file *file = (struct file *)(v & ~3);
	u64 *tmp;

	tmp = files.lookup(&file);
	if (!tmp)
		return 0;
	u64 pid = bpf_get_current_pid_tgid();
	u64 stackid = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
	u64 *val;
	u64 zero = 0;

	val = stack_hash.lookup_or_init(&stackid, &zero);
	(*val)++;
	return 0;
}
int trace_recvfrom_ret(struct pt_regs *ctx)
{
	u64 ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	u64 *tmp;

	tmp = pids.lookup(&pid);
	if (!tmp)
		return 0;
	accepts.perf_submit(ctx, &ret, sizeof(ret));
	return 0;
}
*/
""")
b.attach_kprobe(event="inet_accept", fn_name="trace_inet_accept")
b.attach_kprobe(event="sock_sendmsg", fn_name="trace_sock_sendmsg")
b.attach_kprobe(event="inet_recvmsg", fn_name="trace_sock_recvmsg")
b.attach_kprobe(event="inet_stream_connect", fn_name="trace_inet_stream_connect")
b.attach_kretprobe(event="sock_sendmsg", fn_name="trace_sock_op_ret")
b.attach_kretprobe(event="inet_recvmsg", fn_name="trace_sock_op_ret_recv")
b.attach_kprobe(event="sk_filter", fn_name="trace_sk_filter")
b.attach_kretprobe(event="sk_filter", fn_name="trace_sk_filter_ret")
#b.attach_kprobe(event="tcp_setsockopt", fn_name="trace_sk_method")
#b.attach_kprobe(event="tcp_close", fn_name="trace_sk_method")
#b.attach_kretprobe(event="__fdget", fn_name="trace_fdget")
#b.attach_kretprobe(event="SyS_recvfrom", fn_name="trace_recvfrom_ret")

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("port", ct.c_ulonglong),
        ("bytes", ct.c_ulonglong),
        ("time", ct.c_ulonglong),
        ("opname", ct.c_char * 32),
    ]

def print_pid(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%s pid %d tgid %d did %s on port %s with %s bytes" % (event.time, event.pid >> 32,
        event.pid & ((1 << 32)-1), event.opname, event.port, event.bytes))

#def print_accept(cpu, data, size):
#    event = ct.cast(data, ct.POINTER(ct.c_ulonglong)).contents
#    print("pid %d tgid %d is accepted" % (event.value >> 32, event.value & ((1 << 32)-1)))

def print_accept(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ct.c_ulonglong)).contents
    print("recvfrom ret %s" % (event.value))
	
b["accepts"].open_perf_buffer(print_accept)
b["sends"].open_perf_buffer(print_pid)
stack_traces = b.get_table("stack_traces")
stack_hash = b.get_table("stack_hash")
while 1:
    b.kprobe_poll()
    for k,v in stack_hash.items():
        stack = stack_traces.walk(k.value)
        for addr in stack:
            print("   %s" % b.ksym(addr))
        print("\n")
    stack_hash.clear()
