#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>

/**
 * @brief 尝试从映射中查找给定键对应的值，如果不存在则尝试进行初始化
 *
 * @param map 映射对象的指针
 * @param key 要查找或初始化的键的指针
 * @param init 初始化值的指针，用于在键不存在时插入映射
 *
 * @return 如果查找或初始化成功，则返回键对应的值的指针，否则返回0
 */
static __always_inline 
void *bpf_map_lookup_or_try_init(void *map,const void *key,const void *init) {
  void *val;			// 存储查找结果或初始化后的值
  long err;				// 存储映射操作的返回值

	// 尝试从映射中查找给定键对应的值
  val = bpf_map_lookup_elem(map, key);
  if (val) {
		return val;		// 如果找到，直接返回值的指针
	}

	// 如果键不存在，尝试初始化映射，使用BPF_NOEXIST标志表示键不能已存在
  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  if (err && err != -EEXIST) {
		// 如果更新映射失败且不是因为键已存在，则返回0
		return 0;
	}

	// 重新尝试从映射中查找给定键对应的值
  return bpf_map_lookup_elem(map, key);
}

#endif /* __MAPS_BPF_H */
