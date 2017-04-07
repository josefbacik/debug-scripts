from bcc import BPF
import ctypes as ct

b = BPF(text="""
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

BPF_HASH(holders, struct sock *);
BPF_PERF_OUTPUT(events);

int trace_sock_sendmsg(struct pt_regs *ctx, struct socket *socket)
{
	struct sock *sk = socket->sk;
	struct inet_sock *inet = inet_sk(sk);
	u16 port = sk->__sk_common.skc_num;
	//port = ntohs(port);
	if (port == 0xcea) {
		u64 val = port;
		events.perf_submit(ctx, &val, sizeof(val));
	}
	return 0;
}
""")
b.attach_kprobe(event="sock_sendmsg", fn_name="trace_sock_sendmsg")

def print_pid(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ct.c_ulonglong)).contents
    print("pid %d is responsible" % (event.value))

b["events"].open_perf_buffer(print_pid)
while 1:
    b.kprobe_poll()
