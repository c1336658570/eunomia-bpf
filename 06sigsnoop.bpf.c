// ./ecc 06sigsnoop.bpf.c 
// sudo ./ecli run package.json
// sudo cat /sys/kernel/debug/tracing/trace_pipe
// 捕获进程发送信号的系统调用集合，使用 hash map 保存状态
// 定义了一个 eBPF 程序，用于捕获进程发送信号的系统调用，包括 kill、tkill 和 tgkill。
// 它通过使用 tracepoint 来捕获系统调用的进入和退出事件，并在这些事件发生时执行指定的探针函数，
// 例如 probe_entry 和 probe_exit。


#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240     // 定义哈希映射的最大条目数
#define TASK_COMM_LEN 16      // 进程名称的最大长度

// 定义事件结构体，用于存储追踪到的信息
struct event {
  unsigned int pid;             // 进程ID
  unsigned int tpid;            // 目标进程ID
  int sig;                      // 信号
  int ret;                      // 系统调用返回值
  char comm[TASK_COMM_LEN];     // 进程名称
};

// 定义哈希映射，将线程ID映射到事件结构体
struct {
  __uint(type, BPF_MAP_TYPE_HASH);      // 定义映射类型为哈希映射
  __uint(max_entries, MAX_ENTRIES);     // 定义最大条目数
  __type(key, __u32);                   // 定义键类型为32位无符号整数
  __type(value, struct event);          // 定义值类型为事件结构体
} values SEC(".maps");                  // 将映射放在名为"values"的maps节中

// 定义probe_entry函数，用于处理系统调用的进入阶段
static int probe_entry(pid_t tpid, int sig) {
  struct event event = {};    // 初始化事件结构体
  __u64 pid_tgid;
  __u32 tid;

  pid_tgid = bpf_get_current_pid_tgid();
  tid = (__u32)pid_tgid;
  event.pid = pid_tgid >> 32;     // 获取当前进程ID
  event.tpid = tpid;              // 获取目标进程ID
  event.sig = sig;                // 获取信号
  bpf_get_current_comm(event.comm, sizeof(event.comm));     // 获取当前进程名称
  bpf_map_update_elem(&values, &tid, &event, BPF_ANY);      // 将事件更新到哈希映射中
  return 0;
}

// 定义probe_exit函数，用于处理系统调用的退出阶段
static int probe_exit(void *ctx, int ret) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  struct event *eventp;

  eventp = bpf_map_lookup_elem(&values, &tid);    // 在哈希映射中查找事件
  if (!eventp) return 0;

  eventp->ret = ret;        // 更新事件的系统调用返回值
  bpf_printk("PID %d (%s) sent signal %d ", eventp->pid, eventp->comm, eventp->sig);
  bpf_printk("to PID %d, ret = %d", eventp->tpid, ret);

cleanup:
  bpf_map_delete_elem(&values, &tid);   // 从哈希映射中删除事件
  return 0;
}

// 定义tracepoint/syscalls/sys_enter_kill的处理函数
SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx) {
  pid_t tpid = (pid_t)ctx->args[0];
  int sig = (int)ctx->args[1];

  return probe_entry(tpid, sig);      // 调用probe_entry处理系统调用进入阶段
}

// 定义tracepoint/syscalls/sys_exit_kill的处理函数
SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx) {
  return probe_exit(ctx, ctx->ret);   // 调用probe_exit处理系统调用退出阶段
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
