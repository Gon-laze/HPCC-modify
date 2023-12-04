#ifndef _ELASTIC_SKETCH_H_
#define _ELASTIC_SKETCH_H_

#include "HeavyPart.h"
#include "LightPart.h"

//bucket num以及tot_memory_in_bytes都是模板当中的非类型形参
//由于是整形类型的非类型形参，因此需要在编译时能够确定对应值
//非类型形参在模板内部可以按照常量去处理
template<int bucket_num, int tot_memory_in_bytes>
class ElasticSketch
{
public:
    //heavy part所占用的内存大小 bucket num代表elastic heavy part可用的bucket的数目
    static constexpr int heavy_mem = bucket_num * COUNTER_PER_BUCKET * (sizeof(five_tuples) + sizeof(flow_features));
    //light part（count min）可用的内存大小即为总大小 - heavy part的大小
    static constexpr int light_mem = tot_memory_in_bytes - heavy_mem;
    //Elastic的heavy part以及light part
    HeavyPart<bucket_num> heavy_part;
    LightPart<light_mem> light_part;

    ElasticSketch()
    {
        for(int i = 0;i < bucket_num;++i)
        {
            for(int j = 0;j < COUNTER_PER_BUCKET;++j)
            {
                heavy_part.buckets[i].key[j].initialize();
                heavy_part.buckets[i].val[j].initialize();
            }
        }
    }
    ~ElasticSketch(){}
    void clear() 
    {
        heavy_part.clear();
        light_part.clear();
    }

    //插入方法
    void insert(five_tuples *key, double time, uint16_t size)
    {
        five_tuples swap_key;
        //换出值，由于light part只统计total bytes，所以换出值是uint32_t类型的
        uint32_t swap_val;
        int result = heavy_part.insert(key, &swap_key, swap_val, time, size);
        switch(result)
        {
            //插入成功
            case 0: return;
            //发生替换，需要插入到light_part，插入值为swap_val
            case 1:{
                //换出的这个counter之前已经进行过一次换出了
                if(HIGHEST_BIT_IS_1(swap_val))
                    light_part.insert(&swap_key, GetCounterVal(swap_val));
                //换出的这个counter之前还没有进行过换出
                else
                    light_part.swap_insert(&swap_key, GetCounterVal(swap_val));
                return;
            }
            //未发生替换，就直接插入到light_part(仍然是只插入total_size)
            case 2: light_part.insert(key, size);  return;
            default:
                printf("error return value !\n");
                exit(1);
        }
    }
    //quick insert就是只管插入heavy part
    void quick_insert(five_tuples *key, double time, uint16_t size)
    {
        heavy_part.quick_insert(key, time, size);
    }

    //我们的函数查询结果如果为大流会将结果放置到feature_result，并最终返回true,如果不是大流则返回false，并只将查询到的total_size放置于size_result当中
    bool query(five_tuples *key, flow_features &feature_result, uint32_t &size_result)
    {
        bool query_result = heavy_part.query(key, feature_result);
        //如果heavy part中没有查询到结果
       // std::cout << "query here" << std::endl;
        if(query_result == false)
        {
            //查询到的light部分结果
            size_result = light_part.query(key);
            return false;
        }
        //查到了结果但是heavy part结果最高位为1（代表之前执行过换出的操作）
        else
        {
            if(HIGHEST_BIT_IS_1(feature_result.total_size))
            {
                //查询到的light部分结果
                uint32_t light_result = light_part.query(key);
                feature_result.total_size = GetCounterVal(feature_result.total_size) + light_result;
            }
            return true;
        }
    }

    int get_bucket_num() 
    { 
        return heavy_part.get_bucket_num(); 
    }

    void get_heavy_hitters(int threshold, std::vector<std::pair<five_tuples, flow_features>> & results_greater,  std::vector<std::pair<five_tuples, flow_features>> & results_less)
    {
        //相当于遍历整个heavy part
        for (int i = 0; i < bucket_num; ++i) 
        {
            for (int j = 0; j < MAX_VALID_COUNTER; ++j) 
            {
                //空的counter，直接跳过
                if(heavy_part.buckets[i].key[j].empty() == true){
                    continue;
                }
                five_tuples key = heavy_part.buckets[i].key[j];
                flow_features val;
                uint32_t light_total_size;
                //由于是对heavy part中非空的key做查询，因此最后一定可以查询到
                query(&key, val, light_total_size);
                //当查询到的流的total_size大于阈值时
                if (val.total_size >= threshold) 
                    results_greater.push_back(std::make_pair(key, val));
                else
                    results_less.push_back(std::make_pair(key, val));
            }
        }
    }

    /*void *operator new(size_t sz)
    {
        constexpr uint32_t alignment = 64;
        size_t alloc_size = (2 * alignment + sz) / alignment * alignment;
        void *ptr = ::operator new(alloc_size);
        void *old_ptr = ptr;
        void *new_ptr = ((char*)std::align(alignment, sz, ptr, alloc_size) + alignment);
        ((void **)new_ptr)[-1] = old_ptr;

        return new_ptr;
    }

    void operator delete(void *p)
    {
        ::operator delete(((void**)p)[-1]);
    }*/
};

#endif // _ELASTIC_SKETCH_H_
