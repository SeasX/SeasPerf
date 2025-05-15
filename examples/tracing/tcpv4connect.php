<?php
$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
        u32 pid = bpf_get_current_pid_tgid();

        // stash the sock ptr for lookup on return
        currsock.update(&pid, &sk);

        return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid();

        struct sock **skpp;
        skpp = currsock.lookup(&pid);
        if (skpp == 0) {
                return 0;       // missed entry
        }

        if (ret != 0) {
                // failed to send SYNC packet, may not have populated
                // socket __sk_common.{skc_rcv_saddr, ...}
                currsock.delete(&pid);
                return 0;
        }

        // pull in details
        struct sock *skp = *skpp;
        u32 saddr = skp->__sk_common.skc_rcv_saddr;
        u32 daddr = skp->__sk_common.skc_daddr;
        u16 dport = skp->__sk_common.skc_dport;

        // output
        bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

        currsock.delete(&pid);

        return 0;
}
EOT;

$ebpf = new Bpf(["text" => $bpf_text]);
# header
printf("%-6s %-12s %-16s %-16s %-4s\n", "PID", "COMM", "SADDR", "DADDR","DPORT");
# format output
while (true) {
    try {
        list($task, $pid, $cpu, $flags, $ts, $msg) =$ebpf->trace_fields();
        list($tag, $saddr_hs, $daddr_hs, $dport_s) = explode(" ", $msg, 4);

        printf("%-6d %-12.12s %-16s %-16s %-4s\n",
            $pid,
            $task,
            long2ip(unpack('V', pack('H*', $saddr_hs))[1]),
            long2ip(unpack('V', pack('H*', $daddr_hs))[1]),
            $dport_s
        );
        flush();
    } catch (Exception $e) {
        continue;
    }
}