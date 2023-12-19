// ./ecc 07execsnoop.bpf.c 07execsnoop.h
// sudo ./ecli run package.json
// 捕获进程执行事件，通过 perf event array 向用户态打印输出

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "07execsnoop.h"

// 定义 BPF Map，用于存储性能事件数组
// 这个map可以不用指定max_entries，因为在libbpf中会默认设置max_entries为系统cpu个数。
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);      // 指定映射的类型为性能事件数组
  __uint(key_size, sizeof(u32));                    // 指定键的大小为 u32
  __uint(value_size, sizeof(u32));                  // 指定值的大小为 u32
} events SEC(".maps");                              // 定义映射并指定在 .maps 段

// 定义 TRACEPOINT 子系统的 sys_enter_execve 钩子
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
  u64 id;
  pid_t pid, tgid;
  struct event event = {0};     // 初始化 event 结构体，并置零
  struct task_struct *task;

  // 获取当前用户的 UID 和当前进程的 ID 和 TGID
  uid_t uid = (u32)bpf_get_current_uid_gid();
  id = bpf_get_current_pid_tgid();
  tgid = id >> 32;

  // 填充 event 结构体的成员
  event.pid = tgid;
  event.uid = uid;
  task = (struct task_struct *)bpf_get_current_task();
  event.ppid = BPF_CORE_READ(task, real_parent, tgid);
  // 获取系统调用参数中的命令字符串指针
  char *cmd_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
  // 读取命令字符串并复制到 event 结构体的 comm 成员
  bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);
  // 输出性能事件。BPF_F_CURRENT_CPU: 表示将事件发送到当前 CPU 的性能事件缓冲区。BPF_F_CURRENT_CPU 是一个标志，表示使用当前 CPU 的缓冲区。
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
