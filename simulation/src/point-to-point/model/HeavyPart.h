#ifndef _HEAVYPART_H_
#define _HEAVYPART_H_

#include "param.h"
#include "BOBHash32.h"
//ns3环境下不能使用该加速方法
//#define USING_SIMD_ACCELERATION
#ifdef USING_SIMD_ACCELERATION
#include <immintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#endif // USING_SIMD_ACCELERATION
template<int bucket_num>
class HeavyPart
{
public:
    alignas(64) Bucket buckets[bucket_num];
    //在heavy part也使用BoBHash，而非先前的Hash方法
    BOBHash32 *bobhash = NULL;
    HeavyPart() 
	{
        this->clear();
        //初始化BOBHash32对象，和LightPart基本一致
        std::random_device rd;
        bobhash = new BOBHash32(rd() % MAX_PRIME32);
    }
    ~HeavyPart() {}

    void clear() 
	{
    	memset(buckets, 0, sizeof(Bucket) * bucket_num);
    }

    //插入（牵扯到置换问题），因此还有部分参数为置换出去的结果
    //key传指针主要是为了解决计算BoBHash时需要做强制类型转换的问题
    int insert(five_tuples *key, five_tuples *swap_key, uint32_t &swap_val, double time, uint16_t size) 
	{
        //fp = finger print，即待插入元素的key值
		five_tuples fp;
		fp.copy(*key);
		//待插入的bucket的位置
		int pos = CalculateBucketPos(key);
		//min_counter_val对应flow features当中的total_bytes，我们的大小流分流以总字节为标准
		uint32_t min_counter_val;
		int min_counter;
		do{
			/* find if there has matched bucket */
			int matched = -1, empty = -1;
			min_counter = 0;
			//最小值初始化为第0个counter内流的total_size
			min_counter_val = GetCounterVal(buckets[pos].val[0].total_size);
			//开始遍历所有的counter（但不遍历最后一个counter，因为那是存放vote-的地方）
			for(int i = 0; i < COUNTER_PER_BUCKET - 1; i++)
			{
				//如果当前counter的key和fp匹配一致，那么就代表找到了可以直接插入的地方
				if(buckets[pos].key[i].compare(fp) == true){
					matched = i;
					break;
				}
				//如果当前的counter为空，且在此counter前还没有找到过空的counter
				if(buckets[pos].key[i].empty() == true && empty == -1){
					empty = i;
					break;
				}
				//如果当前counter的total_size小于最小min_counter_val，那么就更新min_counter_val以及最小counter的位置
				if(min_counter_val > GetCounterVal(buckets[pos].val[i].total_size)){
					min_counter = i;
					min_counter_val = GetCounterVal(buckets[pos].val[i].total_size);
				}
			}

			/* if matched */
			//如果匹配到了
			if(matched != -1)
			{
				//就更新统计特征
				buckets[pos].val[matched].update(time,size);
				return 0;
			}

			/* if there has empty bucket */
			//如果当前存在空的counter，就把待插入元素放到里面
			if(empty != -1)
			{
				buckets[pos].key[empty] = fp;
				buckets[pos].val[empty].update(time,size);
				return 0;
			}
		}while(0);

		/* update guard val and comparison */
		//此时，需要进行置换操作了，最后一个counter位置用于放vote-
		uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER].total_size;
		//vote- 增加一个size的大小
		guard_val = UPDATE_GUARD_VAL(guard_val,size);

		//比较min_counter_val和vote-的值，如果不满足交换条件就直接更新guard_val
		if(!JUDGE_IF_SWAP(GetCounterVal(min_counter_val), guard_val))
		{
			buckets[pos].val[MAX_VALID_COUNTER].total_size = guard_val;
			return 2;
		}
		//此时可以进行更新，我们就将counter中原来存储的流踢出，保留新的流
		*(swap_key) = buckets[pos].key[min_counter];
		//换出的时候就先不计算流特征了，仅保留总字节数这一特征，但注意换出的时候不能GetVal，因为后续插入light part时还有一次判断
		swap_val = buckets[pos].val[min_counter].total_size;

		//保留新的流
		//将vote-重新设置为0
		buckets[pos].val[MAX_VALID_COUNTER].total_size = 0;
		//将待插入元素插入到min_counter的位置
		buckets[pos].key[min_counter].copy(fp);
		//先初始化min_counter处的val
		buckets[pos].val[min_counter].initialize();
		//最高位为1用于标记当前的counter经历过踢出的操作
		buckets[pos].val[min_counter].update(time,0x80000000 & size);

		return 1;
    }
    //快速插入（未牵扯到置换问题）
    int quick_insert(five_tuples *key, double time, uint16_t size) {
    	five_tuples fp = *key;
    	//计算出待插入的位置，fp这里值为five tuples
    	int pos = CalculateBucketPos(key);
    	uint32_t min_counter_val;
    	int min_counter;
    	do{
    		/* find if there has matched bucket */
    		int matched = -1, empty = -1;
    		min_counter = 0;
    		//#define GetCounterVal(val) ((uint32_t)((val) & 0x7FFFFFFF))
    		//寻找所有counter最小的值
    		min_counter_val = GetCounterVal(buckets[pos].val[0].total_size);
    		for(int i = 0; i < COUNTER_PER_BUCKET - 1; i++)
			{
    			//如果这个counter中的key和fp匹配，那么就找到对应的位置了
    			if(buckets[pos].key[i].compare(fp) == true)
				{
    				matched = i;
    				break;
    			}
    			//如果当前是空的counter，且是第一个空的counter，则修改empty为当前的位置
    			if(buckets[pos].key[i].empty() == true && empty == -1)
				{
    				empty = i;
    			}
    			//如果当前counter非空，也没有匹配到key，且值val小于min_counter_val，那么就更新min_counter的位置，以及min_counter_val
    			if(min_counter_val > GetCounterVal(buckets[pos].val[i].total_size))
				{
    				min_counter = i;
    				min_counter_val = GetCounterVal(buckets[pos].val[i].total_size);
    			}
    		}

    		/* if matched */
    		//如果找到了对应的key，那么就直接插入就可以
    		if(matched != -1)
			{
    			buckets[pos].val[matched].update(time,size);
    			return 0;
    		}

    		/* if there has empty bucket */
    		//如果有空的单元，那么就将当前元素直接放在这个位置
    		if(empty != -1)
			{
    			buckets[pos].key[empty].copy(fp);
    			buckets[pos].val[empty].update(time,size);
    			return 0;
    		}
    		//如果在循环结束的时候，还没有退出该函数，那就说明既没找到空的位置也没有找到匹配的位置
    	}while(0);

    	/* update guard val and comparison */
    	//这个时候就需要做置换了，对统计值最小的那个counter进行修改操作
    	//如果min_val * 8（elastic的置换比率） 小于 guard_val（反对票值），就进行置换
    	//guard_val是当前bucket最后一个counter的val值
    	uint32_t guard_val = buckets[pos].val[MAX_VALID_COUNTER].total_size;
    	//增加vote-
    	guard_val = UPDATE_GUARD_VAL(guard_val,size);

		//当前情况下不用做置换，直接返回2
    	if(!JUDGE_IF_SWAP(GetCounterVal(min_counter_val), guard_val))
		{
    		buckets[pos].val[MAX_VALID_COUNTER].total_size = guard_val;
    		return 2;
    	}
    	//进行了置换，这里只更换key值，旧的统计结果都会保留
    	buckets[pos].val[MAX_VALID_COUNTER].total_size = 0;
    	buckets[pos].key[min_counter].copy(fp);
    	return 1;
    }

    //返回true代表找到了对应的key，false代表没有找到
    bool query(five_tuples *key,flow_features &value) 
	{
    	five_tuples fp = *key;
    	int pos = CalculateBucketPos(key);

    	for(int i = 0; i < MAX_VALID_COUNTER; ++i)
		{
    		//当前的counter匹配成功
    		if(buckets[pos].key[i].compare(fp) == true)
			{
    			value = buckets[pos].val[i];
    			return true;
    		}
    	}
    	return false;
    }

    int get_memory_usage() 
	{
    	return bucket_num * sizeof(Bucket);
    }
    
	int get_bucket_num() 
	{
    	return bucket_num;
    }
	
    int CalculateBucketPos(five_tuples *key) 
	{
    	//hash val是BoBHash哈希的结果
    	uint32_t hash_val = (uint32_t)bobhash->run((const char*)key, sizeof(five_tuples));
    	//返回一个bucket index，采用mod的方式去获取index
    	return hash_val % bucket_num;
    }
};

#endif //_HEAVYPART_H_