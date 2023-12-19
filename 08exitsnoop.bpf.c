// ./ecc 08exitsnoop.bpf.c 08exitsnoop.h
// sudo ./ecli run package.json
// 在 eBPF 中使用 exitsnoop 监控进程退出事件，使用 ring buffer 向用户态打印输出

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "08exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义环形缓冲区映射，最大允许 256,000 个条目
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);    // 256MB
} rb SEC(".maps");

// sched_process_exit 事件的跟踪点处理程序
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
  struct task_struct *task;
  struct event *e;      // 用于存储进程退出信息的事件结构体
  pid_t pid, tid;       // 进程 ID 和线程 ID
  u64 id, ts, *start_ts, start_time = 0;      // ID、时间戳、指针以及起始时间

  // 获取正在退出的线程/进程的 PID 和 TID
  id = bpf_get_current_pid_tgid();
  pid = id >> 32;
  tid = (u32)id;

  // 忽略子线程退出事件
  if (pid != tid) {
    return 0;
  }

  // 在 BPF 环形缓冲区中保留一个样本的空间
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  // 用数据填充样本
  task = (struct task_struct *)bpf_get_current_task();
  start_time = BPF_CORE_READ(task, start_time);

  // 计算进程的持续时间（纳秒）
  e->duration_ns = bpf_ktime_get_ns() - start_time;
  e->pid = pid;
  e->ppid = BPF_CORE_READ(task, real_parent, tgid);               // 获取父进程 ID
  e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;    // 提取退出码
  bpf_get_current_comm(&e->comm, sizeof(e->comm));                // 获取进程的命令名称

  // 将数据发送到用户空间进行后续处理
  bpf_ringbuf_submit(e, 0);
  return 0;
}
