#ifndef SWITCH_NODE_H
#define SWITCH_NODE_H

#include <unordered_map>
#include <ns3/node.h>
#include "qbb-net-device.h"
#include "switch-mmu.h"
#include "pint.h"

#ifdef MODIFY_ON
	#include<chrono>
	#include<queue>
	#include<algorithm>
#endif

#define ELASTIC_ON

#ifdef ELASTIC_ON
    #include "ElasticSketch.h"
    #include "param.h"
    extern "C" 
    {
        #include <pcap.h>
        #include <time.h>
        #include <sys/socket.h>
        #include <sys/types.h>
        #include <dirent.h>
    }
#endif

namespace ns3 {

class Packet;

#ifdef ELASTIC_ON
#else
// *仅针对为了构建数据结构而临时创建的节点类
// !和ns3中服务器节点Node类没有任何关联
template<typename T>
class Data_node{
	T content;
	Data_node<T>*	lchild = 0;
	Data_node<T>*	rchild = 0;
	Data_node<T>*	parent = 0;

	Data_node(T x):content(x){}
};

template<typename T>
class DataElement{

    public:
        std::string		key;
        T				val;

        static bool cmp_greater(const DataElement& x, const DataElement& y)
        {
            return x.val > y.val;
        }
        static bool cmp_less(const DataElement& x, const DataElement& y)
        {
            return x.val < y.val;
        }

        // DataElement(){}
        DataElement(const std::string& k, const T& v):key(k),val(v){}
};

template<typename T>
class Heap{
	// 默认最大容纳1024条信息
	// const MAXSIZE 	= 1024;
    public:
        enum cmp_FunctionType{
            GREATER,
            LESS
        };
        
        std::vector< DataElement<T> >	vec;
        bool (*cmp)(const DataElement<T>& x, const DataElement<T>& y);
        
        inline DataElement<T> top()	{	return (empty()) ? DataElement<T>({}, {}) : vec.front();	}
        inline uint32_t size()	    {	return vec.size();	}
        inline bool empty()		    {	return vec.empty();	}

        void push(const DataElement<T>& x)
        {
            vec.push_back(x);
            // std::cout << "push x: " << x.key << ' ' << x.val << std::endl;
            std::push_heap(vec.begin(), vec.end(), (*cmp));
            return;
        }
        void pop()
        {
            std::pop_heap(vec.begin(), vec.end(), (*cmp));
            vec.pop_back();
            return;
        }
        void realign()
        {
            std::make_heap(vec.begin(), vec.end(), (*cmp));
        }
        uint32_t find(const std::string& k)
        {
            uint32_t index;
            for (index = 0; index<vec.size(); index++)
                if (vec[index].key == k)
                    break;
            if (index >= vec.size())    index = 0xffffffff;
            return index;
        }
        bool renew(const std::string& k, T& val)
        {
            uint32_t index = find(k);
            if (index>=vec.size())	return false;
            
            vec[index].val= val;
            realign();
            return true;
        }
        bool del(const std::string& k)
        {
            uint32_t index = find(k);
            if (index>=vec.size())	return false;
            
            vec[index] = vec.back();
            vec.pop_back();
            realign();
            return true;
        }

        Heap(const cmp_FunctionType& x)
        {
            if (x == GREATER)		cmp = &(DataElement<T>::cmp_greater);
            else if (x == LESS)		cmp = &(DataElement<T>::cmp_less);
        }

};

template<typename T>
class T2T_Heap{
    public:
        Heap<T> 			Top{Heap<T>::LESS};
        Heap<T>				Bottom{Heap<T>::GREATER};

        // !为测试改成了0.45。注意及时改回0.2！！！！
        double superRate = 0.45;

        inline DataElement<T> top()	{	return Top.top();	}
        inline uint32_t size()	    {	return Top.size()+Bottom.size();	}
        inline bool empty()		    {   return Top.empty() && Bottom.empty();	}

        void adjust()
        {
            
            // TODO：边界过于粗糙而导致1条左右的流误判。想办法修正（例如比较Top和Bottom的top()
            // *DONE:新增一个调整环节
            while (Top.size()>uint32_t(size()*superRate) && !Top.empty())	    {	DataElement<T> tmp=Top.top();	Top.pop();	Bottom.push(tmp);	}
            while (Top.size()<uint32_t(size()*superRate) && !Bottom.empty())	{	DataElement<T> tmp=Bottom.top();	Bottom.pop();	Top.push(tmp);	}
            if (Top.empty()==false && Bottom.empty()==false)
            {
                while (Top.top().val > Bottom.top().val)
                {   DataElement<T> tmp1=Top.top(), tmp2=Bottom.top();
                    Top.pop();
                    Bottom.pop();
                    Top.push(tmp2);
                    Bottom.push(tmp1);
                }             
            }
        }
        void push(const DataElement<T>& x)
        {
            if (Top.empty() || Top.top().val>=x.val)	Top.push(x);
            else				                        Bottom.push(x);
            adjust();
        }
        void pop()
        {
            uint32_t tmp;
            tmp = Top.top();
            Top.pop();
            adjust();
        }
        bool renew(const std::string& k, T& val)
        {
            bool isSuccess = Top.renew(k,val) || Bottom.renew(k,val);
            adjust();
            return isSuccess;
        }
        bool del(const std::string& k)
        {
            bool isSuccess = Top.del(k) || Bottom.del(k);
            adjust();
            return isSuccess;
        }
};
#endif


class SwitchNode : public Node{
	static const uint32_t pCnt = 257;	// Number of ports used
	static const uint32_t qCnt = 8;	// Number of queues/priorities used
	uint32_t m_ecmpSeed;
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	// monitor of PFC
	uint32_t m_bytes[pCnt][pCnt][qCnt]; // m_bytes[inDev][outDev][qidx] is the bytes from inDev enqueued for outDev at qidx
	
	uint64_t m_txBytes[pCnt]; // counter of tx bytes

	uint32_t m_lastPktSize[pCnt];
	uint64_t m_lastPktTs[pCnt]; // ns
	double m_u[pCnt];

	#ifdef MODIFY_ON
public:
	// *由RDMAHw.cc迁移而来：专门针对switchNode进行特征测量（因switchNode并没有实例化RdmaHw）
	/******************************
	 * New Stats for switch.h
	 *****************************/
    #ifdef ELASTIC_ON
        ElasticSketch<BUCKET_NUM,TOTAL_MEMORY_IN_BYTES> * elastic = new ElasticSketch<BUCKET_NUM,TOTAL_MEMORY_IN_BYTES>();
        // 仅需记录五元组信息
        // std::set<five_tuples> ftSet;

        // !优先级unorderedmap单独保留：特征与调度分离
        // 流特征优先级
        std::unordered_map<five_tuples, uint32_t, five_tuples_hash, five_tuples_equal> flow_pg_class_table[2];
        // *3是指3个优先级;double为了方便除法
        std::unordered_map<five_tuples, double, five_tuples_hash, five_tuples_equal> flow_pg_pktNum_table[3];
    #else
        //burst的最大包间隔，用于统计流量burst特征信息
        double burst_max_duration = 0.03;
        //用于确定当前使用哪组unordered_map存储测量得到的特征，哪组用于写入当前周期内流的特征
        // 所有的流表，其key均使用流五元组构成的字符串 TODO：重写哈希函数，构建key值为五元组的unordered_map
        // 和包的总个数以及总字节数相关的统计table，
        std::unordered_map<std::string,uint64_t> flow_byte_size_table[2];
        std::unordered_map<std::string,uint64_t> flow_packet_num_table[2];
        //和包间隔相关的统计tables，包间隔特征：max_pkt_interval min_pkt_interval avg_pkt_interval
        std::unordered_map<std::string,double> flow_last_pkt_time_table[2];
        std::unordered_map<std::string,double> flow_first_pkt_time_table[2];
        std::unordered_map<std::string,double> flow_min_pkt_interval_table[2];
        std::unordered_map<std::string,double> flow_max_pkt_interval_table[2];
        std::unordered_map<std::string,double> flow_avg_pkt_interval_table[2];
        //和包大小相关的统计tables，包大小特征：max_pkt_size min_pkt_size avg_pkt_size
        std::unordered_map<std::string,uint16_t> flow_max_pkt_size_table[2];
        std::unordered_map<std::string,uint16_t> flow_min_pkt_size_table[2];
        std::unordered_map<std::string,uint16_t> flow_avg_pkt_size_table[2];
        //和burst相关的统计tables，burst特征：max_burst_size avg_burst_size
        std::unordered_map<std::string,uint64_t> flow_current_burst_size_table[2];
        std::unordered_map<std::string,uint64_t> flow_max_burst_size_table[2];
        std::unordered_map<std::string,uint64_t> flow_avg_burst_size_table[2];
        std::unordered_map<std::string,uint64_t> flow_total_burst_size_table[2];
        std::unordered_map<std::string,uint64_t> flow_burst_num_table[2];
        //和流速率相关的统计tables，flow speed
        std::unordered_map<std::string,double> flow_speed_table[2];


        // std::unordered_map<std::string,uint64_t> flow_byte_size_table;
        // std::unordered_map<std::string,uint64_t> flow_packet_num_table;
        // //和包间隔相关的统计tables，包间隔特征：max_pkt_interval min_pkt_interval avg_pkt_interval
        // std::unordered_map<std::string,double> flow_last_pkt_time_table;
        // std::unordered_map<std::string,double> flow_first_pkt_time_table;
        // std::unordered_map<std::string,double> flow_min_pkt_interval_table;
        // std::unordered_map<std::string,double> flow_max_pkt_interval_table;
        // std::unordered_map<std::string,double> flow_avg_pkt_interval_table;
        // //和包大小相关的统计tables，包大小特征：max_pkt_size min_pkt_size avg_pkt_size
        // std::unordered_map<std::string,uint16_t> flow_max_pkt_size_table;
        // std::unordered_map<std::string,uint16_t> flow_min_pkt_size_table;
        // std::unordered_map<std::string,uint16_t> flow_avg_pkt_size_table;
        // //和burst相关的统计tables，burst特征：max_burst_size avg_burst_size
        // std::unordered_map<std::string,uint64_t> flow_current_burst_size_table;
        // std::unordered_map<std::string,uint64_t> flow_max_burst_size_table;
        // std::unordered_map<std::string,uint64_t> flow_avg_burst_size_table;
        // std::unordered_map<std::string,uint64_t> flow_total_burst_size_table;
        // std::unordered_map<std::string,uint64_t> flow_burst_num_table;
        // //和流速率相关的统计tables，flow speed
        // std::unordered_map<std::string,double> flow_speed_table[2]
        // // 流特征优先级
        // std::unordered_map<std::string, uint32_t> flow_pg_class_table[2];

        // !优先级unorderedmap单独保留：特征与调度分离
        // 流特征优先级
        std::unordered_map<std::string, uint32_t> flow_pg_class_table[2];
        // *3是指3个优先级;double为了方便除法
        std::unordered_map<std::string, double> flow_pg_pktNum_table[3];
    
        T2T_Heap<uint64_t>  TOP_20percent;
        
    #endif

    const uint32_t OLD_DATA = 0;
    const uint32_t CNT_DATA = 1;
    
    uint32_t index = 0;

    void Switch_FeatureGenerator(Ptr<const Packet> p, CustomHeader &ch);
    void Switch_FeaturePrinter();

    uint32_t FlowPrinter_interval = 3;
	void Switch_FlowPrinter();

    /* 为流的老化而设置的变量；*/
    // *先将阈值设大，有需求再改
    const uint64_t  PERIOD_IDLE_THRESHOLD = 5000;
    const double    SIZE_IDLE_THRESHOLD = 0.0;
    const double    AGING_ALPHA_SMALL = 0.1;
    const double    AGING_ALPHA_BIG = 0.9;
    std::unordered_map<std::string, uint64_t> flow_idle_num_table[2];
    std::unordered_map<std::string, double> flow_current_frate_table[2];
    std::unordered_map<std::string, uint64_t> flow_current_size_table[2];


#endif

protected:
	bool m_ecnEnabled;
	uint32_t m_ccMode;
	uint64_t m_maxRtt;

	uint32_t m_ackHighPrio; // set high priority for ACK/NACK

private:
	int GetOutDev(Ptr<const Packet>, CustomHeader &ch);
	void SendToDev(Ptr<Packet>p, CustomHeader &ch);
	static uint32_t EcmpHash(const uint8_t* key, size_t len, uint32_t seed);
	void CheckAndSendPfc(uint32_t inDev, uint32_t qIndex);
	void CheckAndSendResume(uint32_t inDev, uint32_t qIndex);
public:
	Ptr<SwitchMmu> m_mmu;

	static TypeId GetTypeId (void);
	SwitchNode();
	void SetEcmpSeed(uint32_t seed);
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	void ClearTable();
	bool SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch);
	void SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p);

	// for approximate calc in PINT
	int logres_shift(int b, int l);
	int log2apprx(int x, int b, int m, int l); // given x of at most b bits, use most significant m bits of x, calc the result in l bits
};

} /* namespace ns3 */

#endif /* SWITCH_NODE_H */
