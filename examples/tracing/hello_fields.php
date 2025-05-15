<?php
$prog = <<<EOT
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
EOT;
# load BPF program
$ebpf = new Bpf(["text" => $prog]);
$ebpf->attach_kprobe($ebpf->get_syscall_fnname("clone"),"hello");
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