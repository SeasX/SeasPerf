<?php
$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>

struct urandom_read_args {
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};

int printarg(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
EOT;

$b = new Bpf(["text" => $bpf_text]);
$b->attach_tracepoint("random:urandom_read", "printarg");

echo sprintf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "GOTBITS");

while (true) {
    try {
        list($task, $pid, $cpu, $flags, $ts, $msg) = $ebpf->trace_fields();
        printf("%-18.9f %-16s %-6d %s\n", $ts, $task, $pid, $msg);
    } catch (Exception $e) {
        break;
    }
}
