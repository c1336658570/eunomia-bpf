/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SOFTIRQS_H
#define __SOFTIRQS_H

#define MAX_SLOTS	20

// 定义一个结构体 hist 用于表示直方图数据
struct hist {
	__u32 slots[MAX_SLOTS];		// 存储直方图的槽位数据的数组，每个槽位记录某个区间内事件发生的次数
};

#endif /* __SOFTIRQS_H */
