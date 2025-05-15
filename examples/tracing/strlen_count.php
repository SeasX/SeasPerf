<?php
$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
EOT;

$b = new Bpf(["text" => $bpf_text]);
$b->attach_uprobe("c", "strlen", "count");

echo "Tracing strlen()... Hit Ctrl-C to end.\n";
pcntl_signal(SIGINT, "signalHandler");
pcntl_async_signals(true);

# sleep until Ctrl-C
while (true) {
    sleep(99999999);
}

function signalHandler($signo)
{
    global $b;
    switch ($signo) {
        case SIGINT:
            echo sprintf("%10s %s\n", "COUNT", "STRING");
            $counts        = $b->get_table("counts");
            $vals = $counts->values();
            foreach ($vals as $v) {
                $k = unpack("A80c", $v['key']);
                $v = unpack("Qval", $v['value']);
                printf("%10d \"%s\"\n", $v['val'],$k['c']);
            }
            exit(0);
    }
}
