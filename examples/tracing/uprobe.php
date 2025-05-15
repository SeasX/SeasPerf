<?php
if ($argc < 2) {
    fwrite(STDERR, "Usage: php script.php <binary_path> <pid>\n");
    exit(1);
}
$binary = $argv[1];
$pid = intval($argv[2]);

$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>

int test(struct pt_regs *ctx)
{
        bpf_trace_printk("%d---%d\\n",ctx->di,ctx->si);
        return 1;
}
EOT;

$ebpf = new Bpf(["text" => $bpf_text]);
$opt = array("pid"=>$pid);
$ebpf->attach_uprobe($binary,"add","test",$opt);
# header
printf("%-18s %-16s %-6s %s\n", "TIME(s)", "COMM", "PID", "MESSAGE");
# format output
while (true) {
    try {
        list($task, $pid, $cpu, $flags, $ts, $msg) = $ebpf->trace_fields();
        printf("%-18.9f %-16s %-6d %s\n", $ts, $task, $pid, $msg);
        flush();
    } catch (Exception $e) {
        continue;
    }
}