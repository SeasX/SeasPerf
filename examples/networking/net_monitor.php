<?php

if ($argc !== 2) {
    echo "Usage: php {$argv[0]} <net_interface>\n";
    echo "Example: php {$argv[0]} eno1\n";
    exit(1);
}

$INTERFACE = $argv[1];
define("OUTPUT_INTERVAL", 1);

$bpf_text = <<<EOT
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_PERF_OUTPUT(skb_events);
BPF_HASH(packet_cnt, u64, long, 256);

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u32 saddr, daddr;
    long* count = 0;
    long one = 1;
    u64 pass_value = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->ver != 4)
        return 0;
    if (ip->nextp != IP_TCP)
    {
        if (ip -> nextp != IP_UDP)
        {
            if (ip -> nextp != IP_ICMP)
                return 0;
        }
    }

    saddr = ip -> src;
    daddr = ip -> dst;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    count = packet_cnt.lookup(&pass_value);
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&pass_value, &one);
        }
    return -1;
}

EOT;

$b = new Bpf(["text" => $bpf_text]);
$func = $b->load_func("packet_monitor", Bpf::SOCKET_FILTER);
$b->attach_raw_socket($func, $INTERFACE);

$packet_cnt = $b->get_table("packet_cnt");

function decimal_to_ip($int) {
    return long2ip($int);
}

while (true) {
    sleep(OUTPUT_INTERVAL);

    $items = $packet_cnt->values();
    $time = date("Y-m-d H:i:s");

    if (count($items) > 0) {
        echo "\nCurrent packet stats:\n";
    }

    foreach ($items as $entry) {
        $key = unpack("Q", $entry["key"])[1];
        $val = unpack("l", $entry["value"])[1];

        $src = ($key >> 32) & 0xFFFFFFFF;
        $dst = $key & 0xFFFFFFFF;

        echo sprintf(
            "source: %s -> destination: %s count: %d time: %s\n",
            decimal_to_ip($src),
            decimal_to_ip($dst),
            $val,
            $time
        );
    }

    $packet_cnt->clear();
}
