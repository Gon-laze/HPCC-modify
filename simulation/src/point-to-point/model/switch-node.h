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

namespace ns3 {

class Packet;

// *仅针对为了构建数据结构而临时创建的节点类
// !和ns3中服务器节点Node类没有任何关联
// template<typename T>
// class Data_node{
// 	T content;
// 	Data_node<T>*	lchild = 0;
// 	Data_node<T>*	rchild = 0;
// 	Data_node<T>*	parent = 0;

// 	Data_node(T x):content(x){}
// };

// *使用string作为键值key，内容content任意
template<typename T>
class DataElement{
	std::string		key;
	T				val;

	bool cmp_greater(const DataElement& x, const DataElement& y)
	{
		return x.val > y.val;
	}
	bool cmp_less(const DataElement& x, const DataElement& y)
	{
		return x.val < y.val;
	}

	DataElement(T x):val(x){}
};

template<typename T>
class Heap{
	// 默认最大容纳1024条信息
	// const MAXSIZE 	= 1024;

	enum cmp_FunctionType{
		GREATER,
		LESS
	};
	
	std::vector< DataElement<T> >	vec;
	bool (*cmp)(const T& x, const T& y);
	
	inline T top()			{	return (empty()) ? DataElement().val : vec.front().val;	}
	inline uint32 size()	{	return vec.size();	}
	inline bool empty()		{	return vec.empty();	}

	void push(T x)
	{
		vec.push_back(x);
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
	uint32_t search(const std::string& k)
	{
		uint32_t index;
		for (index = 0; index<vec.size(); index++)
			if (vec[index].key == k)
				break;
		return index;
	}
	bool renew(const std::string& k, T& val)
	{
		uint32_t index = search(k);
		if (index>=vec.size())	return false;
		
		vec[index].val= val;
		realign();
		return true;
	}

	Heap(cmp_FunctionType x)
	{
		if (x == GREATER)		cmp = &(DataElement.cmp_greater);
		else if (x == LESS)		cmp = &(DataElement.cmp_less)
	}

};

template<typename T>
class T2T_Heap{
	// std::priority_queue< uint32_t, std::vector<uint32_t>, std::greater<uint32_t> > Top;
	// std::priority_queue< uint32_t, std::vector<uint32_t>, std::less<uint32_t> > Bottom;

	Heap<T> 			Top(LESS);
	Heap<T>				Bottom(GREATER);

	double superRate = 0.2;

	inline T top()			{	return Top.top();	}
	inline uint32_t size()	{	return Top.size()+Bottom.size();	}
	inline bool empty()		{	return Top.empty() && Bottom.empty();	}

	void adjust()
	{
		uint32_t tmp;
		while (Top.size()>uint32_t(size()*superRate))						{	tmp=Top.top();	Top.pop();	Bottom.push(tmp);	}
		while (Top.size()<uint32_t(size()*superRate) && !Bottom.empty())	{	tmp=Bottom.top();	Bottom.pop();	Top.push(tmp);	}
	}
	void push(T x)
	{
		uint32_t tmp;
		if (Top.top()>=x)	Top.push(x);
		else				Bottom.push(x);
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
};


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
	// *由RDMAHw.cc迁移而来：专门针对switchNode进行特征测量（因switchNode并没有实例化RdmaHw）
	/******************************
	 * New Stats for switch.h
	 *****************************/
	//burst的最大包间隔，用于统计流量burst特征信息
	double burst_max_duration = 0.03;
	//用于确定当前使用哪组unordered_map存储测量得到的特征，哪组用于写入当前周期内流的特征
	int index = 0;
	//所有的流表，其key均使用流五元组构成的字符串 TODO：重写哈希函数，构建key值为五元组的unordered_map
	//和包的总个数以及总字节数相关的统计table，
	std::vector<std::unordered_map<std::string,uint64_t>> flow_byte_size_table(2);
	std::vector<std::unordered_map<std::string,uint64_t>> flow_packet_num_table(2);
	//和包间隔相关的统计tables，包间隔特征：max_pkt_interval min_pkt_interval avg_pkt_interval
	std::vector<std::unordered_map<std::string,double>> flow_last_pkt_time_table(2);
	std::vector<std::unordered_map<std::string,double>> flow_first_pkt_time_table(2);
	std::vector<std::unordered_map<std::string,double>> flow_min_pkt_interval_table(2);
	std::vector<std::unordered_map<std::string,double>> flow_max_pkt_interval_table(2);
	std::vector<std::unordered_map<std::string,double>> flow_avg_pkt_interval_table(2);
	//和包大小相关的统计tables，包大小特征：max_pkt_size min_pkt_size avg_pkt_size
	std::vector<std::unordered_map<std::string,uint16_t>> flow_max_pkt_size_table(2);
	std::vector<std::unordered_map<std::string,uint16_t>> flow_min_pkt_size_table(2);
	std::vector<std::unordered_map<std::string,uint16_t>> flow_avg_pkt_size_table(2);
	//和burst相关的统计tables，burst特征：max_burst_size avg_burst_size
	std::vector<std::unordered_map<std::string,uint64_t>> flow_current_burst_size_table(2);
	std::vector<std::unordered_map<std::string,uint64_t>> flow_max_burst_size_table(2);
	std::vector<std::unordered_map<std::string,uint64_t>> flow_avg_burst_size_table(2);
	std::vector<std::unordered_map<std::string,uint64_t>> flow_total_burst_size_table(2);
	std::vector<std::unordered_map<std::string,uint64_t>> flow_burst_num_table(2);
	//和流速率相关的统计tables，flow speed
	std::vector<std::unordered_map<std::string,double>> flow_speed_table(2);

	// 流特征优先级
	std::vector<std::unordered_map<std::string, uint32_t>> flow_pg_class_table(2);

	void Switch_FeatureGenerator(Ptr<const Packet> p, CustomHeader &ch);
	void Switch_FeaturePrinter();

	uint32_t FlowPrinter_interval = 3;
	void Switch_FlowPrinter();
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
