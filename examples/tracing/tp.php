<?php
$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>
struct trace_event_raw_sys_enter_rw__stub {
    __u64 unused;
    long int id;
    __u64 fd;
    char* buf;
    __u64 size;
};

int test(struct trace_event_raw_sys_enter_rw__stub* ctx)
{
        bpf_trace_printk("%s\\n",ctx->size);
        return 1;
}
EOT;

$ebpf = new Bpf(["text" => $bpf_text]);
$ebpf->attach_tracepoint("syscalls:sys_enter_write","test");
# header
printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "MESSAGE");
# format output
while (true) {
    try {
        list($task, $pid, $cpu, $flags, $ts, $msg) =$ebpf->trace_fields();
        printf("%-18.9f %-16s %-6d %s\n", $ts, $task, $pid, $msg);
        flush();
    } catch (Exception $e) {
        continue;
    }
}