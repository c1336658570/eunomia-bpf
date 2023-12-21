// 在 eBPF 中捕获进程打开文件的系统调用集合，使用全局变量过滤进程 pid
// 用户态程序可以使用 BPF 系统调用中的某些特性，
// 如 bpf_obj_get_info_by_fd 和 bpf_obj_get_info，获取 eBPF 对象的信息，包括全局变量的位置和值。
// ./ecc 04opensnoop.bpf.c
// sudo ./ecli run package.json
// sudo cat /sys/kernel/debug/tracing/trace_pipe
// 通过执行 ./ecli -h 命令来查看帮助信息
// ./ecli package.json -h
// sudo ./ecli run package.json --pid_target 123
// sudo cat /sys/kernel/debug/tracing/trace_pipe


#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// 要跟踪的进程ID
const volatile int pid_target = 0;

// 接收一个类型为 struct trace_event_raw_sys_enter 的参数 ctx。这个结构体包含了关于系统调用的信息。
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;   // 获取pid

  if (pid_target && pid_target != pid) {
    return false;
  }
  //使用bpf_printk打印进程信息
  bpf_printk("Process ID: %d enter sys openat\n", pid);
  return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";
