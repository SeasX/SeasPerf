<?php
$prog = <<<EOT
#include <linux/fs.h>

BPF_INODE_STORAGE(inode_storage_map, int);

LSM_PROBE(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	  struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	int *value;

	value = inode_storage_map.inode_storage_get(old_dentry->d_inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		return 0;

	bpf_trace_printk("%d", *value);
	return 0;
}
EOT;

# load BPF program
$ebpf = new Bpf(["text" => $prog]);

# format output
while (true) {
    try {
        $ebpf->trace_print();
    } catch (Exception $e) {
        continue;
    }
} 