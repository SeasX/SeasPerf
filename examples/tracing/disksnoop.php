<?php

define("REQ_WRITE", 1); // from include/linux/blk_types.h

$prog = <<<EOT
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;
    tsp = start.lookup(&req);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("%d %x %d\\n", req->__data_len,
                         req->cmd_flags, delta / 1000);
        start.delete(&req);
    }
}
EOT;

$b = new Bpf(["text" => $prog]);

// attach trace_start
if ($b->get_kprobe_functions("blk_start_request")) {
    $b->attach_kprobe("blk_start_request", "trace_start");
}
$b->attach_kprobe("blk_mq_start_request", "trace_start");

// attach trace_completion
if ($b->get_kprobe_functions("__blk_account_io_done")) {
    $b->attach_kprobe("__blk_account_io_done", "trace_completion");
} elseif ($b->get_kprobe_functions("blk_account_io_done")) {
    $b->attach_kprobe("blk_account_io_done", "trace_completion");
} else {
    $b->attach_kprobe("blk_mq_end_request", "trace_completion");
}

printf("%-18s %-2s %-7s %8s\n", "TIME(s)", "T", "BYTES", "LAT(ms)");

$start = 0;

while (true) {
    $fields = $b->trace_fields();
    list($task, $pid, $cpu, $flags, $ts, $msg) = $fields;

    $parts = preg_split('/\s+/', $msg);

    if (count($parts) < 3) continue;

    list($bytes_s, $bflags_s, $us_s) = $parts;

    $bflags = intval($bflags_s, 16);

    if ($bflags & REQ_WRITE) {
        $type_s = "W";
    } else {
        $type_s = "R";
    }
    $ms = intval($us_s) / 1000.0;

    printf("%-18.9f %-2s %-7s %8.2f\n", $ts, $type_s, $bytes_s, $ms);
}
