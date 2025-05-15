<?php
function cb($cpu,$data,$size) {
    $event = unpack("Qcpu/Qts/Qmagic/A16msg", $data);
    if ($event === false) {
        echo "error.\n";
        return;
    }
    printf("[%d] %.6f: %x %s\n", $event['cpu'], $event['ts'] / 1000000, $event['magic'],$event['msg']);
}
$prog = <<<EOT
BPF_PERF_OUTPUT(events);
BPF_ARRAY(counters, u64, 10);
int do_sys_clone(void *ctx) {
  struct {
    u64 cpu;
    u64 ts;
    u64 magic;
    char msg[16];
  } data = {bpf_get_smp_processor_id(),bpf_ktime_get_ns(), 0x12345678,"Hello, world!"};
  int rc;
  if ((rc = events.perf_submit(ctx, &data, sizeof(data))) < 0)
    bpf_trace_printk("perf_output failed: %d\\n", rc);
  int zero = 0;
  u64 *val = counters.lookup(&zero);
  if (val) lock_xadd(val, 1);
  return 0;
}
EOT;

$ebpf = new Bpf(["text" => $prog]);
$event_name = $ebpf->get_syscall_fnname("clone");
$ebpf->attach_kprobe($event_name,"do_sys_clone");
$ebpf->events->open_perf_buffer("cb");
echo("Tracing... Hit Ctrl-C to end.\n");
while (true) {
    try {
        $ebpf->perf_buffer_poll();
        flush();
    } catch (Exception $e) {
        exit;
    }
}