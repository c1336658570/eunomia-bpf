// ./ecc 05bashreadline.bpf.c
// sudo ./ecli run package.json
// sudo cat /sys/kernel/debug/tracing/trace_pipe

// 在 eBPF 中使用 uprobe 捕获 bash 的 readline 函数调用
// uprobe 是一种用于捕获用户空间函数调用的 eBPF 的探针，我们可以通过它来捕获用户空间程序调用的系统函数。

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

/* 
 * u[ret]probe部分定义支持自动附加的格式：
 * u[ret]probe/二进制文件:函数[+偏移量]
 * 
 * 二进制文件可以是绝对/相对路径或文件名；后者通过bpf_program__attach_uprobe_opts解析为完整的二进制路径。
 * 
 * 指定uprobe+确保我们执行严格匹配；要么指定"uprobe"（此时无法进行自动附加），要么为自动附加指定上述格式。
 */
// 定义eBPF程序，该程序作为uretprobe插入到/bin/bash的readline函数中
// 这段代码的作用是在 bash 的 readline 函数返回时执行指定的 BPF_KRETPROBE 函数，即 printret 函数。
// 通过 SEC 宏来定义 uprobe 探针，并使用 BPF_KRETPROBE 宏来定义探针函数。
// 在 SEC 宏中，我们需要指定 uprobe 的类型、要捕获的二进制文件的路径和要捕获的函数名称。这表示我们要捕获的是 /bin/bash 二进制文件中的 readline 函数。
// 使用 BPF_KRETPROBE 宏来定义探针函数，这里的 printret 是探针函数的名称，const void *ret 是探针函数的参数，它代表被捕获的函数的返回值。
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret) {
 char str[MAX_LINE_SIZE];     // 定义字符数组，用于存储读取到的字符串
 char comm[TASK_COMM_LEN];    // 定义字符数组，用于存储进程的名称（comm）
 u32 pid;                     // 定义32位无符号整数，用于存储进程ID

 if (!ret)
  return 0;

 bpf_get_current_comm(&comm, sizeof(comm));   // 获取当前进程的名称（comm）

 pid = bpf_get_current_pid_tgid() >> 32;      // 获取当前进程的PID
 bpf_probe_read_user_str(str, sizeof(str), ret);    // 从用户空间读取 readline 函数的返回值，并将其存储在 str 数组中。

 bpf_printk("PID %d (%s) read: %s ", pid, comm, str);   // 打印相关信息到内核日志

 return 0;
};

char LICENSE[] SEC("license") = "GPL";
