// 捕获进程执行事件，通过 perf event array 向用户态打印输出

#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

// 定义一个常量 TASK_COMM_LEN，表示进程名的最大长度
#define TASK_COMM_LEN 16

// 定义一个结构体 event，用于存储与进程相关的信息
struct event {
  int pid;          // 进程ID
  int ppid;         // 父进程ID
  int uid;          // 用户ID
  int retval;       // 系统调用返回值
  bool is_exit;     // 表示事件是否为进程退出事件的布尔值
  char comm[TASK_COMM_LEN];  // 进程名数组
};

#endif /* __EXECSNOOP_H */
