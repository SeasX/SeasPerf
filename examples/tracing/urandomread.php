<?php
$bpf_text = <<<EOT
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
EOT;

$b = new Bpf(["text" => $bpf_text]);

echo sprintf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "GOTBITS");

while (true) {
    try {
        list($task, $pid, $cpu, $flags, $ts, $msg) = $ebpf->trace_fields();
        printf("%-18.9f %-16s %-6d %s\n", $ts, $task, $pid, $msg);
    } catch (Exception $e) {
        break;
    }
}
