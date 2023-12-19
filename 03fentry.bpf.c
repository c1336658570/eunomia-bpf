// 在 eBPF 中使用 fentry 监测捕获 unlink 系统调用。
// 使用 BPF 的 fentry 和 fexit 探针来跟踪 Linux 内核函数 do_unlinkat。
// ./ecc 03fentry.bpf.c
// sudo ./ecli run package.json
// sudo cat /sys/kernel/debug/tracing/trace_pipe

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义 fentry 探针
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

// 定义 fexit 探针
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}
