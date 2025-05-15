<?php
$prog = <<<EOT
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
EOT;

$b = new Bpf(["text" => $prog]);

$b->attach_kprobe($b->get_syscall_fnname("sync"), "do_trace");

echo "Tracing for quick sync's... Ctrl-C to end\n";

$start = 0;

while (true) {
    list($task, $pid, $cpu, $flags, $ts, $ms) =  $b->trace_fields();

    if ($start === 0) $start = $ts;
    $ts -= $start;

    printf("At time %.2f s: multiple syncs detected, last %s ms ago\n", $ts, $ms);
}
