// 在 eBPF 中使用 exitsnoop 监控进程退出事件，使用 ring buffer 向用户态打印输出

#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

// 定义任务命令名称的最大长度
#define TASK_COMM_LEN 16

// 定义文件名的最大长度
#define MAX_FILENAME_LEN 127

// 定义用于存储进程退出信息的事件结构体
struct event {
  int pid;                          // 进程 ID
  int ppid;                         // 父进程 ID
  unsigned exit_code;               // 进程退出码
  unsigned long long duration_ns;   // 进程持续时间（纳秒）
  char comm[TASK_COMM_LEN];         // 进程命令名称
};

#endif /* __BOOTSTRAP_H */
