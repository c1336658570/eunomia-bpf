// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang

// ./ecc 10softirqs.bpf.c
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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "10softirqs.h"
#include "10bits.bpf.h"
#include "10maps.bpf.h"

const volatile bool targ_dist = false;		// 控制是否显示执行时间分布
const volatile bool targ_ns = false;			// 控制是否以纳秒为单位显示执行时间

// 定义一个 eBPF 数组映射，用于存储中断处理程序的开始时间戳
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

// 定义全局数组，用于存储每个软中断的计数信息
__u64 counts[NR_SOFTIRQS] = {};
// 定义全局数组，用于存储每个软中断的执行时间总和
__u64 time[NR_SOFTIRQS] = {};
// 定义全局数组，用于存储每个软中断的执行时间分布情况
struct hist hists[NR_SOFTIRQS] = {};

/**
 * @brief 处理软中断入口事件的函数
 * @param vec_nr 软中断向量号
 * @return 0 表示处理成功
 */
static int handle_entry(unsigned int vec_nr) {
  u64 ts = bpf_ktime_get_ns();		// 获取当前时间戳
  u32 key = 0;

  bpf_map_update_elem(&start, &key, &ts, BPF_ANY);		// 更新开始时间戳映射
  return 0;
}

/**
 * @brief 处理软中断出口事件的函数
 * @param vec_nr 软中断向量号
 * @return 0 表示处理成功
 */
static int handle_exit(unsigned int vec_nr) {
  u64 delta, *tsp;
  u32 key = 0;

	// 检查软中断向量号是否超过数组的长度
  if (vec_nr >= NR_SOFTIRQS) {
		return 0;
	}
	// 查找开始时间戳
  tsp = bpf_map_lookup_elem(&start, &key);
  if (!tsp) {
		return 0;
	}
	// 计算中断处理程序的执行时间
  delta = bpf_ktime_get_ns() - *tsp;
	// 如果不是纳秒，转换为微秒
	if (!targ_ns) {
		delta /= 1000U;
	}

  if (!targ_dist) {
		// 如果不显示执行时间分布，累加中断计数和执行时间总和
    __sync_fetch_and_add(&counts[vec_nr], 1);
    __sync_fetch_and_add(&time[vec_nr], delta);
  } else {
		// 如果显示执行时间分布，更新中断执行时间分布直方图
    struct hist *hist;
    u64 slot;
		
    hist = &hists[vec_nr];
		// 计算槽位
		slot = log2(delta);
    if (slot >= MAX_SLOTS) {
			slot = MAX_SLOTS - 1;
		}
		// 更新槽位计数
    __sync_fetch_and_add(&hist->slots[slot], 1);
  }

  return 0;
}

/**
 * @brief 定义 eBPF tracepoint 入口函数，用于捕获软中断入口事件
 * @param vec_nr 软中断向量号
 * @return 0 表示处理成功
 */
SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry_btf, unsigned int vec_nr) {
  return handle_entry(vec_nr);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit_btf, unsigned int vec_nr) {
  return handle_exit(vec_nr);
}

/**
 * @brief 定义 raw tracepoint 入口函数，用于捕获软中断入口事件
 * @param vec_nr 软中断向量号
 * @return 0 表示处理成功
 */
SEC("raw_tp/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr) {
  return handle_entry(vec_nr);
}

SEC("raw_tp/softirq_exit")
int BPF_PROG(softirq_exit, unsigned int vec_nr) { 
	return handle_exit(vec_nr);
}

char LICENSE[] SEC("license") = "GPL";
