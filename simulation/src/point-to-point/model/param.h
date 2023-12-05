#ifndef _PARAM_H_
#define _PARAM_H_

// #include <x86intrin.h>
#include <cstring>
#include <cstdint>
#include <random>
#include <string>
#include <memory>
#include <iostream>
#include <cmath>

//burst的时间间隔限定为0.03 = 30ms
#define BURST_THRESHOLD 0.03
// !保持恒等式： COUNTER_PER_BUCKET = MAX_VALID_COUNTER+1
#define COUNTER_PER_BUCKET 5
#define MAX_VALID_COUNTER 4
// TODO: 更改BUCKET_NUM
#define BUCKET_NUM 11
// !TOTAL_MEMORY_IN_BYTES不要过小
#define TOTAL_MEMORY_IN_BYTES 20000
#define ALIGNMENT 64

#define COUNTER_PER_WORD 8
#define BIT_TO_DETERMINE_COUNTER 3
#define K_HASH_WORD 1


#define KEY_LENGTH_4 4
#define KEY_LENGTH_13 13

#define CONSTANT_NUMBER 2654435761u

//Elastic Sketch统计结果的最高位需要保留
#define GetCounterVal(val) ((uint32_t)((val) & 0x7FFFFFFF))

#define JUDGE_IF_SWAP(min_val, guard_val) ((guard_val) > ((min_val) << 3))

#define UPDATE_GUARD_VAL(guard_val, size) ((guard_val) + size)

#define SWAP_MIN_VAL_THRESHOLD 5

#define HIGHEST_BIT_IS_1(val) ((val) & 0x80000000)

struct five_tuples {
	//32bit srcip 32bit dstip 16bit srcport 16bit dstport 8bit protocol
	uint8_t flow_key[13];
	//构造函数
	five_tuples() {
		for(int i = 0;i < 13;++i){
			flow_key[i] = 0;
		}
	}
	five_tuples(uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport, uint8_t protocol) {
		*((uint32_t *)flow_key) = srcip;
		*((uint32_t *)(flow_key + 4)) = dstip;
		*((uint16_t *)(flow_key + 8)) = srcport;
		*((uint16_t *)(flow_key + 10)) = dstport;
		*((uint8_t *)(flow_key + 12)) = protocol;
	}
	void initialize() {
		for(int i = 0;i < 13;++i){
			flow_key[i] = 0;
		}
	}
	//定义：five_tuples 之间的比较函数
	bool compare(five_tuples a) {
		bool flag = true;
		for(uint32_t i = 0;i < sizeof(flow_key);++i){
			if(flow_key[i] != a.flow_key[i]){
				flag = false;
				break;
			}
		}
		return flag;
	}
	void copy(five_tuples a) {
		for(uint32_t i = 0;i < sizeof(flow_key);++i){
			flow_key[i] = a.flow_key[i];
		}
	}
	//定义：判断当前的flow_key是否为空
	bool empty() {
		bool flag = true;
		for(uint32_t i = 0;i < sizeof(flow_key);++i){
			if(flow_key[i] != 0){
				flag = false;
				break;
			}
		}
		return flag;
	}

	bool operator<(const five_tuples& y)
	{
		for (uint32_t i=0; i<13; i++)
		{
			if (this->flow_key[i] < y.flow_key[i])
				return true;
			else if (this->flow_key[i] > y.flow_key[i])
				return false;
		}
		return false;
	}
};

// *为five_tuples能够直接转化成unorderedmap而采用的hash<...>以及equal<...>类
struct five_tuples_hash{
	// 为简化只考虑前64字节来hash(sip, dip)
	size_t operator()(const five_tuples& x) const
	{
		// uint32_t ans = 0;
		// for (uint32_t i=0; i<4; i++)
		// 	ans = (ans << 8) | x.flow_key[i];
		// return std::hash<uint32_t>()(ans);
		
		// uint64_t ans = 0;
		// for (uint64_t i=0; i<8; i++)
		// 	ans = (ans << 8) | x.flow_key[i];
		// return std::hash<uint64_t>()(ans);

		uint64_t ans0 = 0, ans1 = 0;
		for (uint64_t i=0; i<8; i++)
			ans0 = (ans0 << 8) | x.flow_key[i];
		for (uint64_t i=8; i<16; i++)
			ans1 = (ans1 << 8) | x.flow_key[i];
		return std::hash<uint64_t>()(ans0 ^ ans1);
	}
};
struct five_tuples_equal{
	// 为简化只考虑前32字节来hash(sip)
	bool operator()(const five_tuples& x, const five_tuples& y) const noexcept
	{
		bool ans = true;
		for (uint32_t i=0; i<13; i++)
			ans = (ans && (x.flow_key[i]==y.flow_key[i]));
		return ans;
	}
};

struct flow_features {
	//size and num
	uint32_t total_size = 0;
	uint32_t pkt_num = 0;
	//packet time 
	double first_pkt_time = -1.0;
	double last_pkt_time = 0.0;
	//packet interval
	double min_pkt_interval = 99999.0;
	double max_pkt_interval = 0.0;
	double avg_pkt_interval = 0.0;
	//packet size
	uint32_t min_pkt_size = 65535;
	uint32_t max_pkt_size = 0;
	uint32_t avg_pkt_size = 0;
	//flow burst
	uint32_t max_burst_size = 0;
	uint32_t total_burst_size = 0;
	uint32_t current_burst_size = 0;
	uint16_t burst_num = 0;
	uint32_t avg_burst_size = 0;
	//flow speed
	double flow_speed = 0;
	flow_features() {
		total_size = 0;
		pkt_num = 0;
		first_pkt_time = -1.0;
		last_pkt_time = 0.0;
		min_pkt_interval = 99999.0;
		max_pkt_interval = 0.0;
		avg_pkt_interval = 0.0;
		min_pkt_size = 65535;
		max_pkt_size = 0;
		avg_pkt_size = 0;
		max_burst_size = 0;
		total_burst_size = 0;
		current_burst_size = 0;
		burst_num = 0;
		avg_burst_size = 0;
		flow_speed = 0;
	}
	//初始化flow feature的函数
	void initialize() {
		total_size = 0;
		pkt_num = 0;
		first_pkt_time = -1.0;
		last_pkt_time = 0.0;
		min_pkt_interval = 99999.0;
		max_pkt_interval = 0.0;
		avg_pkt_interval = 0.0;
		min_pkt_size = 65535;
		max_pkt_size = 0;
		avg_pkt_size = 0;
		max_burst_size = 0;
		total_burst_size = 0;
		current_burst_size = 0;
		burst_num = 0;
		avg_burst_size = 0;
		flow_speed = 0;
	}
	//更新flow feature的函数
	void update(double time,uint32_t size){
		total_size += size;
		pkt_num += 1;
		min_pkt_size = std::min(min_pkt_size,GetCounterVal(size));
		max_pkt_size = std::max(max_pkt_size,GetCounterVal(size));
		avg_pkt_size = GetCounterVal(total_size) / pkt_num;
		//当前数据包是第一个数据包
		if(first_pkt_time < 0.0){
			first_pkt_time = time;
			last_pkt_time = time;
			current_burst_size = GetCounterVal(size);
		}
		else{
			double pkt_interval = time - last_pkt_time;
			last_pkt_time = time;
			min_pkt_interval = std::min(min_pkt_interval,pkt_interval);
			max_pkt_interval = std::max(max_pkt_interval,pkt_interval);
			avg_pkt_interval = (last_pkt_time - first_pkt_time) / (pkt_num - 1);
			flow_speed = (double)(total_size) / (last_pkt_time - first_pkt_time) / 1024; //MBps
			//上一周期的burst已经结束
			if(pkt_interval > BURST_THRESHOLD){
				max_burst_size = std::max(max_burst_size,current_burst_size);
				total_burst_size += current_burst_size;
				burst_num += 1;
				current_burst_size = GetCounterVal(size);
				avg_burst_size = total_burst_size / burst_num;
			}
			//burst未结束
			else{
				current_burst_size += GetCounterVal(size);
			}
		}
	}
};

//bucket是elastic sketch heavy part的最小单元，每个bucket包含一个key vector和一个value vector
//两个vector的size均为COUNTER_PER_BUCKET，默认使用8即可
struct Bucket
{
	five_tuples key[COUNTER_PER_BUCKET];
	flow_features val[COUNTER_PER_BUCKET];
};


#endif
