// ./ecc 02kprobe-link.bpf.c
// sudo ./ecli run package.json 
// sudo cat /sys/kernel/debug/tracing/trace_pipe

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 测和捕获在 Linux 内核中执行的 unlink 系统调用。在do_unlinkat函数的入口和退出处放置钩子，实现对该系统调用的跟踪。
// dfd（文件描述符）和name（文件名结构体指针）。
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name) {
  pid_t pid;uretprobe
  const char *filename;

  pid = bpf_get_current_pid_tgid() >> 32;
  filename = BPF_CORE_READ(name, name);
  bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
  return 0;
}

// 当从do_unlinkat函数退出时，它会被触发。此kretprobe的目的是捕获函数的返回值（ret）。
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
  return 0;
}