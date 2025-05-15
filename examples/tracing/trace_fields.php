<?php
$prog = <<<EOT
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
EOT;
# load BPF program
$b = new Bpf(["text" => $prog]);
$b->attach_kprobe($b->get_syscall_fnname("clone"),"hello");
# header
echo sprintf("%s %s\n", "PID", "MESSAGE");
# format output
$b->trace_print("{1} {5}");
