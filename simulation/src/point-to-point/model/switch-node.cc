#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include <cmath>

#ifdef MODIFY_ON
	#include<chrono>
#endif

namespace ns3 {

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;
}

int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){
	// look up entries
	auto entry = m_rtTable.find(ch.dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldPause(inDev, qIndex)){
		device->SendPfc(qIndex, 0);
		m_mmu->SetPause(inDev, qIndex);
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);
	}
}

void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	int idx = GetOutDev(p, ch);
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(idx, qIndex, p->GetSize())){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());
				m_mmu->UpdateEgressAdmission(idx, qIndex, p->GetSize());
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}
		m_bytes[inDev][idx][qIndex] += p->GetSize();
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){
	SendToDev(packet, ch);
	return true;
}

void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	FlowIdTag t;
	p->PeekPacketTag(t);
	if (qIndex != 0){
		uint32_t inDev = t.GetFlowId();
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
		if (m_ecnEnabled){
			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
			if (egressCongested){
				PppHeader ppp;
				Ipv4Header h;
				p->RemoveHeader(ppp);
				p->RemoveHeader(h);
				h.SetEcn((Ipv4Header::EcnType)0x03);
				p->AddHeader(h);
				p->AddHeader(ppp);
			}
		}
		//CheckAndSendPfc(inDev, qIndex);
		CheckAndSendResume(inDev, qIndex);
	}
	if (1){
		uint8_t* buf = p->GetBuffer();
		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
			if (m_ccMode == 3){ // HPCC
				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
			}else if (m_ccMode == 10){ // HPCC-PINT
				uint64_t t = Simulator::Now().GetTimeStep();
				uint64_t dt = t - m_lastPktTs[ifIndex];
				if (dt > m_maxRtt)
					dt = m_maxRtt;
				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
				double newU;

				/**************************
				 * approximate calc
				 *************************/
				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
				int sft = logres_shift(b,l);
				double fct = 1<<sft; // (multiplication factor corresponding to sft)
				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
				double log_B = log2(B)*fct; // log2(B)*fct
				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
				double qterm = 0;
				double byteTerm = 0;
				double uTerm = 0;
				if ((qlen >> 8) > 0){
					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
					qterm = pow(2, (
								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
								)/fct
							) * 256;
					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
				}
				if (m_lastPktSize[ifIndex] > 0){
					int byte = m_lastPktSize[ifIndex];
					int log_byte = log2apprx(byte, b, m, l);
					byteTerm = pow(2, (
								log_byte + log_1e9 - log_B - log_T
								)/fct
							);
					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
				}
				if (m_maxRtt > dt && m_u[ifIndex] > 0){
					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
					uTerm = pow(2, (
								log_T_dt + log_u - log_T
								)/fct
							) / 8192;
					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
				}
				newU = qterm+byteTerm+uTerm;

				#if 0
				/**************************
				 * accurate calc
				 *************************/
				double weight_ewma = double(dt) / m_maxRtt;
				double u;
				if (m_lastPktSize[ifIndex] == 0)
					u = 0;
				else{
					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
				}
				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
				printf(" %lf\n", newU);
				#endif

				/************************
				 * update PINT header
				 ***********************/
				uint16_t power = Pint::encode_u(newU);
				if (power > ih->GetPower())
					ih->SetPower(power);

				m_u[ifIndex] = newU;
			}
		}
	}
	m_txBytes[ifIndex] += p->GetSize();
	m_lastPktSize[ifIndex] = p->GetSize();
	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
}

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

#ifdef MODIFY_ON
	void SwitchNode::Switch_FeatureGenerator(Ptr<const Packet> p, CustomHeader &ch)
	{
		auto ip2string = [](uint32_t ip)
		{
			return 	 std::to_string(ip>>24 & 0xff)+':'+std::to_string(ip>>16 & 0xff)+':'+std::to_string(ip>>8 & 0xff)+std::to_string(ip & 0xff);
		};
		std::string key_sip = ip2string(ch.sip);
		std::string key_dip = ip2string(ch.dip);
		std::string key_sport;
		std::string key_dport;
		std::string key_proto = std::to_string(ch.l3Prot);
		//TCP
		if(ch.l3Prot == 0x06)
		{
			key_sport = std::to_string(ch.tcp.sport);
			key_dport = std::to_string(ch.tcp.dport);
		}
		//UDP
		else if(ch.l3Prot == 0x11)
		{ 
			key_sport = std::to_string(ch.udp.sport);
			key_dport = std::to_string(ch.udp.dport);
		}
		//NACK && ACK
		else if(ch.l3Prot == 0xFD || ch.l3Prot == 0xFC)
		{
			key_sport = std::to_string(ch.ack.sport);
			key_dport = std::to_string(ch.ack.dport);
		}
		//control protocols and other
		else
		{
			return;
		}
		key_sport = std::to_string(ch.udp.sport);
		key_dport = std::to_string(ch.udp.dport);
		key_proto = std::to_string(ch.l3Prot);
		std::string fivetuples = key_sip + " " + key_dip + " " + key_sport + " " + key_dport + " " + key_proto;
		#ifdef CHECKPOINT_ON
			std::cout << "checkpoint 1 begin\n";
		#endif
		// !用simulator试一试
		// !以下换成了纯payloadsize大小，有需要换回p->Getsize()
		auto current_time = Simulator::Now().GetSeconds();
		auto payload_size = p->GetSize() - ch.GetSerializedSize();
		#ifdef CHECKPOINT_ON
			std::cout << "checkpoint 1 end\n";
		#endif
		//更新流字节数、包个数特征
		flow_byte_size_table[fivetuples] += (uint64_t)(payload_size);
		flow_packet_num_table[fivetuples] += 1;
		// // !临时测试
		// std::cout << p->GetSize() << '\t' << ch.m_headerSize << '\t' << ch.GetSerializedSize() << '\n';
		//当前数据包是当前流上的第一个数据包（上行），则更新流第一个数据包的抵达时间，初始化最大包大小，最小包大小，当前burst等信息
		if(flow_first_pkt_time_table.find(fivetuples) == flow_first_pkt_time_table.end())
		{
			//第一个数据包抵达时间以及上一个数据包抵达时间
			flow_first_pkt_time_table[fivetuples] = current_time;
			flow_last_pkt_time_table[fivetuples] = current_time;
			//初始化平均包大小，最大包大小、最小包大小特征
			//TODO：需要再确认下payloadSize + headerSize是否就是数据包的字节大小
			// !事实证明并不是，大小恒定为(0,20(tcpHeader?这甚至不是完整包大小))。有必要引入Packet指针协助统计
			// !分析大概率是产生包头时用的是PeekHeader，其记录信息时统计包大小用的是ReadU16，由于包是空包而视为大小为0
			// !鉴于（个人）默认使用CPinfo指的是payloadsize，的先只测payloadSize得了，先不管包头
			flow_max_pkt_size_table[fivetuples] = (uint64_t)(payload_size);
			flow_min_pkt_size_table[fivetuples] = (uint64_t)(payload_size);
			flow_avg_pkt_size_table[fivetuples] = (uint64_t)(payload_size);
			//初始化最大包到达间隔，最小包到达间隔，平均包到达间隔
			flow_max_pkt_interval_table[fivetuples] = 0.0;
			flow_min_pkt_interval_table[fivetuples] = 1000000000;
			flow_avg_pkt_interval_table[fivetuples] - 0.0;
			//初始化平均burst
			flow_current_burst_size_table[fivetuples] += (uint64_t)(payload_size);
			flow_max_burst_size_table[fivetuples] = 0;
			flow_total_burst_size_table[fivetuples] = 0;
			flow_avg_burst_size_table[fivetuples] = 0;
			flow_burst_num_table[fivetuples] = 0;
			//初始化流速率特征
			flow_speed_table[fivetuples] = 0.0;


		}
		//若不是第一个数据包，则需要开始计算pkt_interval相关的特征信息并进行其他特征的更新
		else
		{
			//计算包间隔，更新上一个数据包抵达时间
			double pkt_interval = (current_time - flow_last_pkt_time_table[fivetuples]);
			flow_last_pkt_time_table[fivetuples] = current_time;
			//更新平均包大小，最大包大小、最小包大小特征
			flow_max_pkt_size_table[fivetuples] = std::max((uint64_t)flow_max_pkt_size_table[fivetuples], (uint64_t)(payload_size));
			flow_min_pkt_size_table[fivetuples] = std::min((uint64_t)flow_min_pkt_size_table[fivetuples],(uint64_t)(payload_size));
			flow_avg_pkt_size_table[fivetuples] = flow_byte_size_table[fivetuples] / flow_packet_num_table[fivetuples];
			//更新化最大包到达间隔，最小包到达间隔, 平均包到达间隔
			flow_max_pkt_interval_table[fivetuples] = std::max((double)flow_max_pkt_interval_table[fivetuples], pkt_interval);
			flow_min_pkt_interval_table[fivetuples] = std::min((double)flow_min_pkt_interval_table[fivetuples], pkt_interval);
			flow_avg_pkt_interval_table[fivetuples] = (flow_last_pkt_time_table[fivetuples] - flow_first_pkt_time_table[fivetuples]) / flow_packet_num_table[fivetuples];
			//更新流速率
			flow_speed_table[fivetuples] = (double)(flow_byte_size_table[fivetuples]) / ((flow_last_pkt_time_table[fivetuples] - flow_first_pkt_time_table[fivetuples]));
			//更新burst
			//当前数据包间隔小于burst duration，那么继续更新current burst
			if(pkt_interval < burst_max_duration)
			{
				flow_current_burst_size_table[fivetuples] += (uint64_t)(payload_size);
			}
			//当前burst结束，更新全局burst特征信息
			else
			{
				flow_max_burst_size_table[fivetuples] = std::max((uint64_t)flow_max_burst_size_table[fivetuples], (uint64_t)flow_current_burst_size_table[fivetuples]);
				flow_total_burst_size_table[fivetuples] += flow_current_burst_size_table[fivetuples];
				flow_burst_num_table[fivetuples] += 1;
				flow_avg_burst_size_table[fivetuples] = flow_total_burst_size_table[fivetuples] / flow_burst_num_table[fivetuples];
				flow_current_burst_size_table[fivetuples] = (uint64_t)(payload_size);
			}
		}

		// *设置优先级
		// *PLAN A
				if (flow_max_pkt_size_table[fivetuples] <= 1369.5 &&
					flow_avg_burst_size_table[fivetuples] <=6790.036 &&
					flow_avg_pkt_interval_table[fivetuples] <= 0.568 &&
					flow_avg_burst_size_table[fivetuples] > 78.0)
			flow_pg_class_table[fivetuples] = 1;
		else
			flow_pg_class_table[fivetuples] = 2;
		return;
		// *PLAN B
		// if (flow_max_pkt_size_table[fivetuples] <= 0.576)
		// 	flow_pg_class_table[fivetuples] = 1;
		// else if (flow_avg_burst_size_table[fivetuples] <= 257.008 &&
		// 		 flow_min_pkt_size_table[fivetuples] <=54.5)
		// 	flow_pg_class_table[fivetuples] = 1;
		// else
		// 	flow_pg_class_table[fivetuples] = 2;
		// return;
	}
	void SwitchNode::Switch_FeaturePrinter()
	{
		// 如果在流表中找到了当前流
		// for (auto iter : flow_first_pkt_time_table)
		// {
		// 	auto udp_key = iter.first;
		// 	// !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
		// 	if (flow_max_pkt_size_table[udp_key] == 0.0) continue;
			
		// 	std::cout << "\n";
		// 	std::cout.precision(10);
		// 	std::cout << "flow five tuples : " << udp_key << '\n';
		// 	std::cout << "flow speed : " << flow_speed_table[udp_key] << '\n';
		// 	std::cout << "flow max packet interval : " << flow_max_pkt_interval_table[udp_key] << '\n';
		// 	std::cout << "flow max pakcet size : " << flow_max_pkt_size_table[udp_key] << '\n';
		// 	std::cout << "flow min pakcet size : " << flow_min_pkt_size_table[udp_key] << '\n';
		// 	std::cout << "frist arrival: " << flow_first_pkt_time_table[udp_key] << '\n';
		// 	std::cout << "last arrival: " << flow_last_pkt_time_table[udp_key] << '\n';
			
		// 	std::cout << "*flow size: " << flow_byte_size_table[udp_key] << '\n';
		// 	std::cout << "*Pktclass: " << flow_pg_class_table[udp_key] << '\n';

		// 	std::cout << "\n";
		// 	// 需要将流从流表中删除
		// 	// !由于是汇总后一并输出，且使用迭代器，保险起见不再删除
		// 	// flow_first_pkt_time_table.erase(udp_key);
		// }
		uint32_t tmpCount;

		std::vector<uint32_t>	tmp_vec;
		
		std::cout << "\n\n";
		std::cout << "PktClass: High\n";
		tmpCount = 0;
		tmp_vec = std::vector<uint32_t>{};
		for (auto iter : flow_first_pkt_time_table)
		{
			auto udp_key = iter.first;
			// // !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
			if (flow_max_pkt_size_table[udp_key] == 0.0) continue;
			if (flow_pg_class_table[udp_key] == 1)
			{
				tmp_vec.push_back(flow_byte_size_table[udp_key]);
				tmpCount++;
			}

		}
		std::cout << "Total: " << tmpCount << '\n';
		for (auto iter : tmp_vec)
			std::cout << iter << '\n';
		
		std::cout << "\n\n";
		std::cout << "PktClass: mid\n";
		tmpCount = 0;
		tmp_vec = std::vector<uint32_t>{};
		for (auto iter : flow_first_pkt_time_table)
		{
			auto udp_key = iter.first;
			// // !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
			if (flow_max_pkt_size_table[udp_key] == 0.0) continue;
			if (flow_pg_class_table[udp_key] == 2)
			{
				tmp_vec.push_back(flow_byte_size_table[udp_key]);
				tmpCount++;
			}		
		}
		std::cout << "Total: " << tmpCount << '\n';
		for (auto iter : tmp_vec)
			std::cout << iter << '\n';

	}

	// 留作后续调度用：尚未声明
	// void SwitchNode::Switch_PktScheduler(){}
#endif

} /* namespace ns3 */
