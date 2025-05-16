# eBPF Observability for PHP
**phbpf** is specifically designed for PHP, enabling the efficient creation of kernel-level tracing and manipulation programs in Linux systems. Centered around eBPF technology, it offers a rich set of tools and examples to empower PHP developers with robust kernel observability and dynamic instrumentation capabilities within their familiar ecosystem

## ✨ Features
- Natively operate BPF programs with PHP scripts, ideal for rapid development and debugging of eBPF functionalities.
- Adheres to bcc frontend usage patterns, allowing bcc tool projects to be implemented in PHP with minimal effort, including built-in examples.
- Core logic written in C/C++, invoking libbpf and LLVM interfaces.
- Supports common BPF hooks: kprobe/uprobe, tracepoint, etc.
- Operates as an external, independent process for transparent monitoring of running systems and target processes.

## 🛠 Architecture Overview
```text
+-------------+         +---------------------------+
|  PHP Script  | <----> |  PHP Extension Module (C) |
+-------------+         +---------------------------+
                                     |
                                     v
                            +------------------+
                            |   libbpf / BCC   |
                            +------------------+
                                     |
                                     v
                            +------------------+
                            |  eBPF Subsystem  |
                            +------------------+

```

## Screenshot

This example traces a disk I/O kernel function, and populates an in-kernel
power-of-2 histogram of the I/O size. For efficiency, only the histogram
summary is returned to user-level.

```Shell
# php ./examples/tracing/bitehist.php
Tracing... Hit Ctrl-C to end.
^C
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

## 🔗 Dependencies
- PHP 7 / 8
- Kernel with BPF support enabled
- [libbpf](https://github.com/libbpf/libbpf)
- [libbcc >= v0.29.0](https://github.com/iovisor/bcc)
- Clang / LLVM

## 🚀 Quick Start

### Dependency Installation

```bash
# Install llvm / bcc / clang, etc.
For example, on Ubuntu22.04:
sudo apt install bpfcc-tools linux-headers-$(uname -r)
```
**For system or dependency installation issues, see [BCC INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md).**


### Installation
```bash
git clone --recursive https://github.com/guolifu/phbpf.git
cd phbpf
phpize
./configure
make && sudo make install
# Configure php.ini
echo "extension=ebpf.so" >> php.ini
# Run example
php examples/hello_world.php
```

## Contents

### Tracing

Examples:

- examples/tracing/[bitehist.php](examples/tracing/bitehist.php): Block I/O size histogram.
- examples/tracing/[disksnoop.php](examples/tracing/disksnoop.php): Trace block device I/O latency.
- examples/[hello_world.php](examples/hello_world.php): Prints "Hello, World!" for new processes.
- examples/tracing/[stacksnoop](examples/tracing/stacksnoop.php): Trace a kernel function and print all kernel stack traces.
- examples/tracing/[tcpv4connect.php](examples/tracing/tcpv4connect.php): Trace TCP IPv4 active connections.
- examples/tracing/[trace_fields.php](examples/tracing/trace_fields.php): Simple example of printing fields from traced events.
- examples/tracing/[undump.php](examples/tracing/undump.php): Dump UNIX socket packets
- examples/tracing/[urandomread.php](examples/tracing/urandomread.php): A kernel tracepoint example, which traces random:urandom_read.
- examples/tracing/[kvm_hypercall.php](examples/tracing/kvm_hypercall.php): Conditional static kernel tracepoints for KVM entry, exit and hypercal.

#### Tools

> This section is under construction. Please check back later.

<center><a href="images/bcc_tracing_tools_2019.png"><img src="images/bcc_tracing_tools_2019.png" border=0 width=700></a></center>

### Networking

Examples:

- examples/networking/[net_monitor.php](examples/networking/net_monitor.php): Used to monitor network packets on a specified network interface.

## Contributing

We welcome contributions to this project! Please feel free to submit a pull request.
