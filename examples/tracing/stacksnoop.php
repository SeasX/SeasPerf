<?php
if ($argc < 2) {
    echo "USAGE: php stacksnoop.php [-p PID] [-s] [-v] function_name\n";
    exit(1);
}
$function = end($argv) ?? null;
$pid = null;
$offset = false;
$verbose = false;

for ($i = 1; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === "-p" && isset($argv[$i + 1])) {
        $pid = $argv[++$i];
    } elseif ($arg === "-s") {
        $offset = true;
    } elseif ($arg === "-v") {
        $verbose = true;
    } else {
        $function = $arg;
    }
}

if (!$function) {
    echo "USAGE: php stacksnoop.php [-p PID] [-s] [-v] function_name\n";
    exit(1);
}

$filter = $pid ? "if (pid != $pid) { return; }" : "";

$prog = <<<EOT
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 stack_id;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_STACK_TRACE(stack_traces, 128);
BPF_PERF_OUTPUT(events);

void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    $filter
    struct data_t data = {};
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
}
EOT;

$b = new Bpf(["text" => $prog]);
$b->attach_kprobe($function, "trace_stack");

$stack_traces = $b->get_table("stack_traces");
$start_ts = microtime(true);

if ($verbose) {
    printf("%-18s %-12s %-6s %-3s %s\n", "TIME(s)", "COMM", "PID", "CPU", "FUNCTION");
} else {
    printf("%-18s %s\n", "TIME(s)", "FUNCTION");
}

function print_event($cpu, $data, $size) {
    global $b, $function, $offset, $verbose, $start_ts, $stack_traces;

    $event = unpack("Qstack_id/Lpid/A16comm", $data);
    $ts = microtime(true) - $start_ts;

    if ($verbose) {
        printf("%-18.9f %-12s %-6d %-3d %s\n", $ts, $event["comm"], $event["pid"], $cpu, $function);
    } else {
        printf("%-18.9f %s\n", $ts, $function);
    }
    foreach ($stack_traces->values($event['stack_id']) as $fn) {
        echo "\t$fn".PHP_EOL;
    }
    echo PHP_EOL;
}

$b->events->open_perf_buffer("print_event");
while (true) {
    try {
        $b->perf_buffer_poll();
    } catch (Exception $e) {
        exit();
    }
}
