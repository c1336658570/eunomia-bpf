/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BITS_BPF_H
#define __BITS_BPF_H

// 宏，执行原子读取操作
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
// 宏，执行原子写入操作
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = val)

// 计算32位无符号整数的以2为底对数的函数
static __always_inline u64 log2(u32 v) {
  u32 shift, r;								// 用于记录位移和结果的变量

	// 确定在前16位中最高位设置的位置。首先，通过比较 v 和 0xFFFF 得到一个布尔值，
	// 然后左移4位（相当于乘以16），将结果保存在 r 中，接着将 v 右移 r 位。
  r = (v > 0xFFFF) << 4;	// 判断高16位是否含有1,如果含有的话,将16赋给r,如果不含r就是0
  v >>= r;								// 将v右移16位或0位,如果高16位含1就右移16位否则右移0位

	// 重复上面过程,判断8-16位是否含1
  shift = (v > 0xFF) << 3;
  v >>= shift;
  r |= shift;
	// 判断4-8位是否含1
  shift = (v > 0xF) << 2;
  v >>= shift;
  r |= shift;
	// 判断2-4位是否含1
  shift = (v > 0x3) << 1;
  v >>= shift;
  r |= shift;

	// 判断1位是否含1
  r |= (v >> 1);	// 将所有的位移组合得到最终结果

  return r;				// 返回以2为底的对数
}

// 计算64位无符号整数的以2为底对数的函数
static __always_inline u64 log2l(u64 v) {
  u32 hi = v >> 32;						// 提取64位整数的高32位

  if (hi)
    return log2(hi) + 32;			// 如果高位不为零，计算log2并加上32
  else
    return log2(v);						// 否则，计算低32位的log2
}

#endif /* __BITS_BPF_H */
