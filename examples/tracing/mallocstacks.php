<?php
if ($argc < 2) {
    echo "USAGE: mallocstacks PID [NUM_STACKS=1024]\n";
    exit(1);
}
$pid    = (int)$argv[1];
$stacks = ($argc == 3 && is_numeric($argv[2]) && (int)$argv[2] > 0) ? $argv[2] : "1024";

$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>

BPF_HASH(calls, int);
BPF_STACK_TRACE(stack_traces, {$stacks});

int alloc_enter(struct pt_regs *ctx, size_t size) {
    int key = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    if (key < 0)
        return 0;

    u64 zero = 0, *val;
    val = calls.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val) += size;
    }
    return 0;
};
EOT;

$ebpf = new Bpf(["text" => $bpf_text]);
$ebpf->attach_uprobe("c", "malloc", "alloc_enter", ["pid" => $pid]);
echo "Attaching to malloc in pid {$pid}, Ctrl+C to quit.\n";

pcntl_signal(SIGINT, "signalHandler");

pcntl_async_signals(true);

# sleep until Ctrl-C
while (true) {
    sleep(99999999);
}

function signalHandler($signo)
{
    global $ebpf;
    global $pid;
    switch ($signo) {
        case SIGINT:
            $calls        = $ebpf->get_table("calls");
            $stack_traces = $ebpf->get_table("stack_traces");
            $calls_vals   = $calls->values();

            $mapped = array_map(function ($val) {
                return [
                    'stack_id' => unpack("L", $val['key'])[1],
                    'value'    => unpack("Q", $val['value'])[1]
                ];
            }, $calls_vals);

            usort($mapped, function($first, $sec) {
                if ($first['value'] == $sec['value']) {
                    return 0;
                }
                return ($first['value'] < $sec['value']) ? 1 : -1;
            });

            foreach ($mapped as $entry) {
                $stack_id = $entry['stack_id'];
                $value = $entry['value'];

                printf("%d bytes allocated at:\n", $value);

                if ($stack_id > 0) {
                    $stack = $stack_traces->values($stack_id, $pid);
                    foreach ($stack as $addr) {
                        printf("\t%s\n", $addr);
                    }
                    printf("    %d\n\n", $value);
                }
            }
            exit(0);
    }
}

