// 在 eBPF 中使用 kprobe 监测捕获 unlink 系统调用
// ./ecc 01minimal.bpf.c
// sudo ./ecli run package.json
// sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF triggered sys_enter_write"
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义一个 handle_tp 函数并使用 SEC 宏把它附加到 sys_enter_write tracepoint
// ctx本来是具体类型的参数， 但是由于我们这里没有使用这个参数，因此就将其写成void *类型。
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;   // 获取进程PID
  if (pid_filter && pid != pid_filter) {
    return 0;
  }
  // /sys/kernel/debug/tracing/trace_pipe
  bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
  return 0;
}