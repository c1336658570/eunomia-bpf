/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HARDIRQS_H
#define __HARDIRQS_H

// 定义一个常量，表示结构体中数组的最大长度
#define MAX_SLOTS	20

// 定义一个结构体，用于存储信息
struct info {
	__u64 count;									// 64位整数，用于存储计数值
	__u32 slots[MAX_SLOTS];				// 32位整数数组，用于存储槽位计数，数组长度为 MAX_SLOTS
};

#endif /* __HARDIRQS_H */
