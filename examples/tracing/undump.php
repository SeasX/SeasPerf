<?php
$pid = null;
$hexdump = false;

foreach ($argv as $index => $arg) {
    if ($arg === "-p" && isset($argv[$index + 1])) {
        $pid = intval($argv[$index + 1]);
    } elseif ($arg === "--hexdump") {
        $hexdump = true;
    }
}

$bpf_prog = <<<EOT
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/aio.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/af_unix.h>

#define MAX_PKT 512
struct recv_data_t {
    u32 recv_len;
    u8  pkt[MAX_PKT];
};

BPF_PERCPU_ARRAY(unix_data, struct recv_data_t, 1);
BPF_PERF_OUTPUT(unix_recv_events);

int trace_unix_stream_read_actor(struct pt_regs *ctx)
{
    u32 zero = 0;
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    FILTER_PID

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct recv_data_t *data = unix_data.lookup(&zero);
    if (!data)
        return 0;

    unsigned int data_len = skb->len;
    if (data_len > MAX_PKT)
        return 0;

    void *iodata = (void *)skb->data;
    data->recv_len = data_len;

    bpf_probe_read(data->pkt, data_len, iodata);
    unix_recv_events.perf_submit(ctx, data, data_len + sizeof(u32));

    return 0;
}
EOT;

if ($pid !== null) {
    $filter = "if (pid != $pid) { return 0; }";
    $bpf_prog = str_replace("FILTER_PID", $filter, $bpf_prog);
} else {
    $bpf_prog = str_replace("FILTER_PID", "", $bpf_prog);
}
// initialize BPF
$b = new Bpf(["text" => $bpf_prog]);
$b->attach_kprobe("unix_stream_read_actor", "trace_unix_stream_read_actor");

echo $pid ? "Tracing PID $pid UNIX socket packets ... Hit Ctrl-C to end\n"
          : "Tracing UNIX socket packets ... Hit Ctrl-C to end\n";

function print_recv_pkg($cpu,$data,$size){
    $recv_len = unpack("L", substr($data, 0, 4))[1];
    $pkt = substr($data, 4, $recv_len);
    global $pid;
    global $hexdump;
    if ($pid) {
        echo "PID \033[1;31m$pid\033[0m ";
    }

    echo "Recv \033[1;31m$recv_len\033[0m bytes\n";
    if ($hexdump) {
        echo chunk_split(bin2hex($pkt), 32, "\n");
    } else {
        echo "    ";
        for ($i = 0; $i < $recv_len; $i++) {
            printf("%02x ", ord($pkt[$i]));
            if (($i + 1) % 16 == 0) echo "\n    ";
        }
        echo "\n";
    }
}
$b->unix_recv_events->open_perf_buffer("print_recv_pkg");

while (true) {
    try {
        $b->perf_buffer_poll();
    } catch (Exception $e) {
        exit();
    }
}
