<?php
$prog = <<<EOT
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    struct bpf_pidns_info ns = {};

    if(bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info)))
    return 0;
    data.pid = ns.pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
EOT;
$stat = stat("/proc/self/ns/pid");
$dev = $stat["dev"];
$ino = $stat["ino"];
$prog = str_replace("DEV", strval($dev), $prog);
$prog = str_replace("INO", strval($ino), $prog);

# load BPF program
$b    = new Bpf(["text" => $prog]);
$b->attach_kprobe($b->get_syscall_fnname("clone"), "hello");

# header
printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "MESSAGE");

# process event
$start = 0;
function print_event($cpu, $data, $size) {
    global $start;
    $event = unpack("Qpid/Qts/A16comm", $data);
    if ($start == 0) {
        $start = $event['ts'];
    }
    $time_s = ($event['ts'] - $start) / 1000000000.0;
    printf("%-18.9f %-16s %-6d %s\n", $time_s, $event['comm'], $event['pid'], "Hello, perf_output!");
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