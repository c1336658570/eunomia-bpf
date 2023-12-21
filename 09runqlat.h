#ifndef __RUNQLAT_H
#define __RUNQLAT_H

// 定义头文件09runqlat.h，用来给用户态处理从内核态上报的事件

#define TASK_COMM_LEN	16		// 定义任务名的最大长度
#define MAX_SLOTS	26				// 定义直方图槽的最大数量

// 定义直方图结构体
struct hist {
	__u32 slots[MAX_SLOTS];			// 直方图槽数组，存储时间间隔在各个槽内的计数
	char comm[TASK_COMM_LEN];		// 任务名数组，存储相关任务的名字
};

#endif /* __RUNQLAT_H */
