<?php
$prog = <<<EOT
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct data_t data = {};

    // Check /sys/kernel/debug/tracing/events/syscalls/sys_enter_setuid/format
    // for the args format
    data.uid = args->uid;
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
EOT;

# load BPF program
$b    = new Bpf(["text" => $prog]);

# header
printf("%-14s %-12s %-6s %s\n", "TIME(s)", "COMMAND", "PID", "UID");

# process event
function print_event($cpu, $data, $size) {
    $event = unpack("Lpid/Luid/Qts/A16comm", $data);
    printf("%-14.3f %-12s %-6d %d\n", $event['ts'] / 1000000000, $event['comm'], $event['pid'], $event['uid']);
}

# loop with callback to print_event
$b->events->open_perf_buffer("print_event");

while (true) {
    try {
        $b->perf_buffer_poll();
    } catch (Exception $e) {
        exit();
    }
}