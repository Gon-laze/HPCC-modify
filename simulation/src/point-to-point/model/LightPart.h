#ifndef _LIGHT_PART_H_
#define _LIGHT_PART_H_

#include "param.h"
#include "BOBHash32.h"

template<int init_mem_in_bytes>
class LightPart
{
public:
	static constexpr int counter_num = init_mem_in_bytes / sizeof(uint32_t);
	BOBHash32 *bobhash = NULL;
	//小流部分不是很关键，目前采取的策略是直接只统计流的总字节数
	uint32_t counters[counter_num];

	LightPart() {
		this->clear();
		//初始化BoBHash
		std::random_device rd;
		bobhash = new BOBHash32(rd() % MAX_PRIME32);
	}
	~LightPart() {
		delete bobhash;
	}

	void clear() {
		memset(counters, 0, sizeof(counters));
	}

	void insert(five_tuples *key, uint32_t size) {
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, sizeof(five_tuples));
		//pos是插入的位置
		uint32_t pos = hash_val % (uint32_t)counter_num;

		/* insert */
		//直接插入更新
		counters[pos] += size;
	}
	void swap_insert(five_tuples *key, uint32_t size) {
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, sizeof(five_tuples));
		//pos是插入的位置
		uint32_t pos = hash_val % (uint32_t)counter_num;

		/* swap_insert */
		if (counters[pos] < size) {
			counters[pos] = size;
		}
	}
	uint32_t query(five_tuples *key) {
		uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, sizeof(five_tuples));
		uint32_t pos = hash_val % (uint32_t)counter_num;
		//返回对应位置的结果
		return counters[pos];
	}

    int get_memory_usage() {
		return counter_num;
	}
};

#endif // _LIGHT_PART_H_
