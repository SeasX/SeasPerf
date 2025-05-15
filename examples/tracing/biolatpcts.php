<?php
$bpf_source = <<<EOT
#include <linux/blkdev.h>
#include <linux/time64.h>

BPF_PERCPU_ARRAY(lat_100ms, u64, 100);
BPF_PERCPU_ARRAY(lat_1ms, u64, 100);
BPF_PERCPU_ARRAY(lat_10us, u64, 100);

RAW_TRACEPOINT_PROBE(block_rq_complete)
{
        // TP_PROTO(struct request *rq, blk_status_t error, unsigned int nr_bytes)
        struct request *rq = (void *)ctx->args[0];
        unsigned int cmd_flags;
        u64 dur;
        size_t base, slot;

        if (!rq->io_start_time_ns)
                return 0;

        dur = bpf_ktime_get_ns() - rq->io_start_time_ns;

        slot = min_t(size_t, div_u64(dur, 100 * NSEC_PER_MSEC), 99);
        lat_100ms.increment(slot);
        if (slot)
                return 0;

        slot = min_t(size_t, div_u64(dur, NSEC_PER_MSEC), 99);
        lat_1ms.increment(slot);
        if (slot)
                return 0;

        slot = min_t(size_t, div_u64(dur, 10 * NSEC_PER_USEC), 99);
        lat_10us.increment(slot);
        return 0;
}
EOT;

$ebpf = new Bpf(["text" => $bpf_source]);

$cur_lat_100ms = $ebpf->lat_100ms;
$cur_lat_1ms =$ebpf->lat_1ms;
$cur_lat_10us = $ebpf->lat_10us;


$last_lat_100ms = array_fill(0, 100, 0);
$last_lat_1ms = array_fill(0, 100, 0);
$last_lat_10us = array_fill(0, 100, 0);

$lat_100ms = array_fill(0, 100, 0);
$lat_1ms = array_fill(0, 100, 0);
$lat_10us = array_fill(0, 100, 0);

function find_pct($req, $total, &$slots, $idx, $counted) {
    while ($idx > 0) {
        $idx--;
        if ($slots[$idx] > 0) {
            $counted += $slots[$idx];
            if (($counted / $total) * 100 >= 100 - $req) {
                break;
            }
        }
    }
    return [$idx, $counted];
}

function calc_lat_pct($req_pcts, $total, &$lat_100ms, &$lat_1ms, &$lat_10us) {
    $pcts = array_fill(0, count($req_pcts), 0);

    if ($total == 0) {
        return $pcts;
    }

    $data = [[100 * 1000, &$lat_100ms], [1000, &$lat_1ms], [10, &$lat_10us]];
    $data_sel = 0;
    $idx = 100;
    $counted = 0;

    for ($pct_idx = count($req_pcts) - 1; $pct_idx >= 0; $pct_idx--) {
        $req = floatval($req_pcts[$pct_idx]);
        while (true) {
            $last_counted = $counted;
            [$gran, $slots] = $data[$data_sel];
            [$idx, $counted] = find_pct($req, $total, $slots, $idx, $counted);
            if ($idx > 0 || $data_sel == count($data) - 1) {
                break;
            }
            $counted = $last_counted;
            $data_sel++;
            $idx = 100;
        }

        $pcts[$pct_idx] = $gran * $idx + $gran / 2;
    }

    return $pcts;
}

echo "Block I/O latency percentile example.\n";


while (true) {
    sleep(3);

    $lat_total = 0;

    for ($i = 0; $i < 100; $i++) {
        $v = $cur_lat_100ms->sum_value($i);
        $lat_100ms[$i] = max($v - $last_lat_100ms[$i], 0);
        $last_lat_100ms[$i] = $v;

        $v =  $cur_lat_1ms->sum_value($i);
        $lat_1ms[$i] = max($v - $last_lat_1ms[$i], 0);
        $last_lat_1ms[$i] = $v;

        $v = $cur_lat_10us->sum_value($i);
        $lat_10us[$i] = max($v - $last_lat_10us[$i], 0);
        $last_lat_10us[$i] = $v;

        $lat_total += $lat_100ms[$i];
    }

    $target_pcts = [50, 75, 90, 99];
    $pcts = calc_lat_pct($target_pcts, $lat_total, $lat_100ms, $lat_1ms, $lat_10us);

    for ($i = 0; $i < count($target_pcts); $i++) {
        echo "p" . $target_pcts[$i] . "=" . intval($pcts[$i]) . "us ";
    }
    echo PHP_EOL;
}
