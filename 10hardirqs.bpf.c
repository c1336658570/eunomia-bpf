// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang

// ./ecc 10hardirqs.bpf.c
// sudo ./ecli run ./package.json
/* 
 * 在 eBPF 中使用 hardirqs 或 softirqs 捕获中断事件
 *
 * hardirqs 和 softirqs 是 Linux 内核中两种不同类型的中断处理程序。
 * 它们用于处理硬件设备产生的中断请求，以及内核中的异步事件。在 eBPF 中，
 * 我们可以使用同名的 eBPF 工具 hardirqs 和 softirqs 来捕获和分析内核中与中断处理相关的信息。
 * 
 * hardirqs 是硬件中断处理程序。当硬件设备产生一个中断请求时，内核会将该请求映射到一个特定的中断向量，
 * 然后执行与之关联的硬件中断处理程序。硬件中断处理程序通常用于处理设备驱动程序中的事件，例如设备数据传输完成或设备错误。
 * 
 * softirqs 是软件中断处理程序。它们是内核中的一种底层异步事件处理机制，用于处理内核中的高优先级任务。
 * softirqs 通常用于处理网络协议栈、磁盘子系统和其他内核组件中的事件。与硬件中断处理程序相比，
 * 软件中断处理程序具有更高的灵活性和可配置性。
 * 
 * 在 eBPF 中，我们可以通过挂载特定的 kprobe 或者 tracepoint 来捕获和分析 hardirqs 和 softirqs。
 * 为了捕获 hardirqs 和 softirqs，需要在相关的内核函数上放置 eBPF 程序。这些函数包括：
 * 对于 hardirqs：irq_handler_entry 和 irq_handler_exit。
 * 对于 softirqs：softirq_entry 和 softirq_exit。
 * 
 * 当内核处理 hardirqs 或 softirqs 时，这些 eBPF 程序会被执行，从而收集相关信息，
 * 如中断向量、中断处理程序的执行时间等。收集到的信息可以用于分析内核中的性能问题和其他与中断处理相关的问题。
 * 
 * 为了捕获 hardirqs 和 softirqs，可以遵循以下步骤：
 * 1.在 eBPF 程序中定义用于存储中断信息的数据结构和映射。
 * 2.编写 eBPF 程序，将其挂载到相应的内核函数上，以捕获 hardirqs 或 softirqs。
 * 3.在 eBPF 程序中，收集中断处理程序的相关信息，并将这些信息存储在映射中。
 * 4.在用户空间应用程序中，读取映射中的数据以分析和展示中断处理信息。
 * 
 * 这段代码是一个 eBPF 程序，用于捕获和分析内核中硬件中断处理程序（hardirqs）的执行信息。
 * 程序的主要目的是获取中断处理程序的名称、执行次数和执行时间，并以直方图的形式展示执行时间的分布。
 */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "10hardirqs.h"
#include "10bits.bpf.h"
#include "10maps.bpf.h"

// 定义映射的最大条目数
#define MAX_ENTRIES	256

// filter_cg 控制是否过滤 cgroup，targ_dist 控制是否显示执行时间的分布等。
const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool do_count = false;

struct irq_key {
	char name[32];
};

// 定义用于存储cgroup信息的映射
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

// 定义开始时间戳的映射
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

// 定义中断处理程序的信息映射
/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct irq_key);
	__type(value, struct info);
} infos SEC(".maps");

// 初始信息结构，用于初始化映射中的值
static struct info zero;

// handle_entry 记录开始时间戳或更新中断计数
static int handle_entry(int irq, struct irqaction *action) {
	// long bpf_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)
	// 从不安全的内核地址unsafe_ptr读取一个以NUL结尾的字符串，将其复制到dst中。其语义与bpf_probe_read_user_str()相同。
	// 成功时，返回字符串的严格正长度，包括结尾的NUL字符。发生错误时，返回一个负值。
	// 目标缓冲器指针 + 目标缓冲区长度 + 内核空间中不安全地址的指针，指向待复制的以NUL结尾的字符串。
	// 如果启用了过滤cgroup，并且当前任务不在指定cgroup中，则返回0
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
		return 0;
	}

  if (do_count) {
		// 如果启用了do_count，统计中断计数
    struct irq_key key = {};
    struct info *info;

		// 读取中断处理程序的名称
    bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
		// 查找或初始化中断信息映射
    info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
    if (!info) {
			return 0;
		}
		// 增加中断计数
    info->count += 1;
    return 0;
  } else {
		// 否则记录开始时间戳
    u64 ts = bpf_ktime_get_ns();
    u32 key = 0;

		// 如果启用了过滤 cgroup，并且当前任务不在指定 cgroup 中，则返回0
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
			return 0;
		}

    bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    return 0;
  }
}

// handle_exit 计算中断处理程序的执行时间，并将结果存储到相应的信息映射中。
static int handle_exit(int irq, struct irqaction *action) {
  struct irq_key ikey = {};
  struct info *info;
  u32 key = 0;
  u64 delta;
  u64 *tsp;

	// 如果启用了过滤 cgroup，并且当前任务不在指定 cgroup 中，则返回0
  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
		return 0;
	}

	// 查找开始时间戳
  tsp = bpf_map_lookup_elem(&start, &key);
  if (!tsp) {
		return 0;
	}

	// 计算中断处理程序执行时间
  delta = bpf_ktime_get_ns() - *tsp;
	// 如果不是纳秒，则转换为微秒
  if (!targ_ns) {
		delta /= 1000U;
	}

	// 读取中断处理程序的名称
  bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));
	// 查找或初始化中断信息映射
  info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
  if (!info) return 0;

  if (!targ_dist) {
		// 不显示执行时间分布，直接累加执行时间
    info->count += delta;
  } else {
		// 显示执行时间分布，计算槽位并累加到相应槽位
    u64 slot;

		// 计算槽位
    slot = log2(delta);
    if (slot >= MAX_SLOTS) {
			slot = MAX_SLOTS - 1;
		}
		// 增加相应槽位的计数
    info->slots[slot]++;
  }

  return 0;
}

/* 
 * 定义了四个 eBPF 程序入口点，分别用于捕获中断处理程序的入口和出口事件。
 * tp_btf 和 raw_tp 分别代表使用 BPF Type Format（BTF）和原始 tracepoints 捕获事件。
 * 这样可以确保程序在不同内核版本上可以移植和运行。
 */
// tracepoint BPF
SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action) {
  return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action) {
  return handle_exit(irq, action);
}

// raw tracepoint
SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action) {
  return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action) {
  return handle_exit(irq, action);
}

char LICENSE[] SEC("license") = "GPL";
