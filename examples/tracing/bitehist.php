<?php
#
# bitehist.php	Block I/O size histogram.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of using histograms to show a distribution.
#
# A Ctrl-C will print the gathered histogram then exit.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Aug-2015	Brendan Gregg	Created this.
# 03-Feb-2019   Xiaozhou Liu    added linear histogram.
# 02-Mar-2025   Wei             Use blk_mq_end_request for newer kernel.

$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(dist_linear);

int trace_req_done(struct pt_regs *ctx, struct request *req)
{
    dist.increment(bpf_log2l(req->__data_len / 1024));
    dist_linear.increment(req->__data_len / 1024);
    return 0;
}
EOT;

# load BPF program
$b = new Bpf(["text" => $bpf_text]);

if ($b->get_kprobe_functions("__blk_account_io_done")) {
    # __blk_account_io_done is available before kernel v6.4.
    $b->attach_kprobe("__blk_account_io_done", "trace_req_done");
} elseif ($b->get_kprobe_functions("blk_account_io_done")) {
    # blk_account_io_done is traceable (not inline) before v5.16.
    $b->attach_kprobe("blk_account_io_done", "trace_req_done");
} else {
    $b->attach_kprobe("blk_mq_end_request", "trace_req_done");
}

# header
echo "Tracing... Hit Ctrl-C to end.\n";

# Set up signal handler for Ctrl-C
pcntl_signal(SIGINT, "signalHandler");
pcntl_async_signals(true);

# sleep until Ctrl-C
while (true) {
    sleep(99999999);
}

function signalHandler($signo) {
    global $b;
    switch ($signo) {
        case SIGINT:
            echo "\nlog2 histogram\n";
            echo "~~~~~~~~~~~~~~\n";
            $b->dist->print_log2_hist("kbytes");
            
            echo "\nlinear histogram\n";
            echo "~~~~~~~~~~~~~~~~\n";
            $b->dist_linear->print_linear_hist("kbytes");
            exit(0);
    }
} 