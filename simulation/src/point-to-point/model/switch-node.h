#ifndef SWITCH_NODE_H
#define SWITCH_NODE_H

#include <unordered_map>
#include <ns3/node.h>
#include "qbb-net-device.h"
#include "switch-mmu.h"
#include "pint.h"

#ifdef MODIFY_ON
	#include<chrono>
#endif

namespace ns3 {

class Packet;

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
	double burst_max_duration = 0.4;
	//所有的流表，其key均使用流五元组构成的字符串 TODO：重写哈希函数，构建key值为五元组的unordered_map
	//和包的总个数以及总字节数相关的统计table，
	std::unordered_map<std::string,uint64_t> flow_byte_size_table;
	std::unordered_map<std::string,uint64_t> flow_packet_num_table;
	//和包间隔相关的统计tables，包间隔特征：max_pkt_interval min_pkt_interval avg_pkt_interval
	std::unordered_map<std::string,double> flow_last_pkt_time_table;
	std::unordered_map<std::string,double> flow_first_pkt_time_table;
	std::unordered_map<std::string,double> flow_min_pkt_interval_table;
	std::unordered_map<std::string,double> flow_max_pkt_interval_table;
	std::unordered_map<std::string,double> flow_avg_pkt_interval_table;
	//和包大小相关的统计tables，包大小特征：max_pkt_size min_pkt_size avg_pkt_size
	std::unordered_map<std::string,uint16_t> flow_max_pkt_size_table;
	std::unordered_map<std::string,uint16_t> flow_min_pkt_size_table;
	std::unordered_map<std::string,uint16_t> flow_avg_pkt_size_table;
	//和burst相关的统计tables，burst特征：max_burst_size avg_burst_size
	std::unordered_map<std::string,uint64_t> flow_current_burst_size_table;
	std::unordered_map<std::string,uint64_t> flow_max_burst_size_table;
	std::unordered_map<std::string,uint64_t> flow_avg_burst_size_table;
	std::unordered_map<std::string,uint64_t> flow_total_burst_size_table;
	std::unordered_map<std::string,uint64_t> flow_burst_num_table;
	//和流速率相关的统计tables，flow speed
	std::unordered_map<std::string,double> flow_speed_table;

	void Switch_FeatureGenerator(Ptr<const Packet> p, CustomHeader &ch);
	void Switch_FeaturePrinter();
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
