// 在 eBPF 中使用 fentry 监测捕获 unlink 系统调用。
// 使用 BPF 的 fentry 和 fexit 探针来跟踪 Linux 内核函数 do_unlinkat。
// ./ecc 03fentry.bpf.c
// sudo ./ecli run package.json
// sudo cat /sys/kernel/debug/tracing/trace_pipe

/*
 * 
 * fentry（function entry）和 fexit（function exit）是 eBPF（扩展的伯克利包过滤器）中的两种探针类型，
 * 用于在 Linux 内核函数的入口和退出处进行跟踪。它们允许开发者在内核函数执行的特定阶段收集信息、修改参数或观察返回值。
 * 这种跟踪和监控功能在性能分析、故障排查和安全分析等场景中非常有用。
 * 
 * 我们可以直接访问函数的指针参数，就像在普通的 C 代码中一样，而不需要使用各种读取帮助程序。
 * fexit 和 kretprobe 程序最大的区别在于，fexit 程序可以访问函数的输入参数和返回值，而 kretprobe 只能访问返回值。
 */

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
