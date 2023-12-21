// ./ecc 09runqlat.bpf.c 09runqlat.h
// sudo ./ecli run package.json -h
// sudo ./ecli run package.json
// 捕获进程调度延迟，以直方图方式记录
// runqlat 是一个 Linux 内核 BPF 程序，通过柱状图来总结调度程序运行队列延迟，显示任务等待运行在 CPU 上的时间长度。
// runqlat 是一种用于监控Linux内核中进程调度延迟的工具。它可以帮助您了解进程在内核中等待执行的时间，并根据这些信息优化进程调度，提高系统的性能。

// 此bpf程序使用的rwa tracepoint，可以查看/sys/kernel/debug/tracing/available_events查看支持的raw tracepoint

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "09runqlat.h"
#include "09bits.bpf.h"
#include "09maps.bpf.h"
#include "09core_fixes.bpf.h"

#define MAX_ENTRIES 10240			// 最大映射项数量
#define TASK_RUNNING 0				// 任务状态

// 全局变量定义：过滤选项和目标选项
const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

// 映射定义：cgroup数组映射，用于过滤 cgroup
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} cgroup_map SEC(".maps");

// 映射定义：起始时间戳映射，用于存储进程入队时的时间戳
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, u64);
} start SEC(".maps");

// 定义零计数的直方图结构体
static struct hist zero;

/// @sample {"interval": 1000, "type" : "log2_hist"}
// 映射定义：直方图映射，用于存储直方图数据，记录进程调度延迟。
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct hist);
} hists SEC(".maps");

// 用于在进程入队时记录其时间戳
static int trace_enqueue(u32 tgid, u32 pid) {
  u64 ts;

	// 如果pid为0，返回
  if (!pid) {
		return 0;
	}
	// 如果指定targ_tgid，但不匹配，返回
  if (targ_tgid && targ_tgid != tgid) {
		return 0;
	}

	// 获取当前时间戳
  ts = bpf_ktime_get_ns();
	// 更新起始时间戳映射
  bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
  return 0;
}

// 函数定义：获取任务的PID命名空间ID，用于获取进程所属的 PID namespace
static unsigned int pid_namespace(struct task_struct *task) {
  struct pid *pid;
  unsigned int level;
  struct upid upid;
  unsigned int inum;

  /*  get the pid namespace by following task_active_pid_ns(),
   *  pid->numbers[pid->level].ns
   */
	// 通过task_active_pid_ns()获取PID命名空间
  pid = BPF_CORE_READ(task, thread_pid);
  level = BPF_CORE_READ(pid, level);
  bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
  inum = BPF_CORE_READ(upid.ns, ns.inum);

  return inum;
}

// 函数定义：处理任务切换事件，用于处理调度切换事件，计算进程调度延迟并更新直方图数据
static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next) {
  struct hist *histp;
  u64 *tsp, slot;
  u32 pid, hkey;
  s64 delta;

	// 根据filter_c的设置判断是否需要过滤cgroup。
	// 如果启用了cgroup过滤，并且当前任务不在指定cgroup中，返回
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
		return 0;
	}

	// 如果之前的进程状态为TASK_RUNNING，则调用trace_enqueue函数记录进程的入队时间。
  if (get_task_state(prev) == TASK_RUNNING) {
    trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));
	}

	// 获取下一个任务的PID
  pid = BPF_CORE_READ(next, pid);

	// 查找下一个进程的入队时间戳，如果找不到，直接返回。
  tsp = bpf_map_lookup_elem(&start, &pid);
  if (!tsp) {
		return 0;
	}
	// 计算调度延迟（delta）
  delta = bpf_ktime_get_ns() - *tsp;
  if (delta < 0) {
    goto cleanup;
  }

	// 根据不同的选项设置（targ_per_process，targ_per_thread，targ_per_pidns），确定直方图映射的键（hkey）。
  if (targ_per_process) {
    hkey = BPF_CORE_READ(next, tgid);   // tgid
	}
  else if (targ_per_thread) {
    hkey = pid;                         // pid
	}
  else if (targ_per_pidns) {
    hkey = pid_namespace(next);         // pid_namespace
	}
  else {
    hkey = -1;
	}
	// 查找或初始化直方图映射，更新直方图数据，最后删除进程的入队时间戳记录。
  // 如果找到元素，它将返回指向现有元素的指针。如果未找到元素，则尝试使用默认值（在这种情况下，默认值是&zero）初始化新元素。
  histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
  if (!histp) {
		goto cleanup;
	}
	// 如果直方图中的任务名称为空，从内核中读取任务名称
  if (!histp->comm[0]) {
    // long bpf_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)
    // 从不安全的内核地址unsafe_ptr读取一个以NUL结尾的字符串，将其复制到dst中。其语义与bpf_probe_read_user_str()相同。
    // 成功时，返回字符串的严格正长度，包括结尾的NUL字符。发生错误时，返回一个负值。
    // 目标缓冲器指针 + 目标缓冲区长度 + 内核空间中不安全地址的指针，指向待复制的以NUL结尾的字符串。
    bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm), next->comm);
	}
	// 根据时间差计算时间槽，并将统计值加1
  if (targ_ms) {  // ms显示
    delta /= 1000000U;
	}
  else {          // us显示
    delta /= 1000U;
	}
  slot = log2l(delta);
  if (slot >= MAX_SLOTS) {
    slot = MAX_SLOTS - 1;
  }
  __sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	// 删除起始时间戳映射中的任务
  bpf_map_delete_elem(&start, &pid);
  return 0;
}

// 定义BPF程序：处理sched_wakeup事件，当一个进程从睡眠状态被唤醒时触发。
SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p) {
	 // 如果启用了cgroup过滤，并且当前任务不在指定cgroup中，返回
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
		return 0;
	}

	// 处理sched_wakeup事件
  return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

// 定义BPF程序：处理sched_wakeup_new事件，当一个新创建的进程被唤醒时触发。
SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p) {
	// 如果启用了cgroup过滤，并且当前任务不在指定cgroup中，返回
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
		return 0;
	}

	// 处理sched_wakeup_new事件
  return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

// 定义BPF程序：处理sched_switch事件，当调度器选择一个新的进程运行时触发。
SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
	// 处理sched_switch事件
  return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
