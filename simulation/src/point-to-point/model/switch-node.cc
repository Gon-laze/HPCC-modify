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

// !!非常关键： switchNode改变实际传输优先级的key-step
void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	int idx = GetOutDev(p, ch);
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			// !改用测量而得到的优先级作为新的qIndex优先级。该部分尚未测试
			// TODO: qindex设置成其他值出错了。为什么？
			#ifdef MODIFY_ON
				auto ip2string = [](uint32_t ip)
				{
					return 	 std::to_string(ip>>24 & 0xff)+':'+std::to_string(ip>>16 & 0xff)+':'+std::to_string(ip>>8 & 0xff)+std::to_string(ip & 0xff);
				};
				std::string key_sip = ip2string(ch.sip);
				std::string key_dip = ip2string(ch.dip);
				std::string key_sport = std::to_string(ch.udp.sport);
				std::string key_dport = std::to_string(ch.udp.dport);
				std::string key_proto = std::to_string(ch.l3Prot);
				std::string fivetuples = key_sip + " " + key_dip + " " + key_sport + " " + key_dport + " " + key_proto;
				// *每次运用优先级都要检测（否则将初始化为0导致一系列错误）！！
				// *多次踩这个坑太荒唐了......
				if (flow_pg_class_table[CNT_DATA].find(fivetuples) != flow_pg_class_table[CNT_DATA].end())
					qIndex = (ch.l3Prot == 0x06 ? 1 : flow_pg_class_table[CNT_DATA][fivetuples]);
				else
					qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
			#else
				qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
			#endif
			
			// qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
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
		flow_byte_size_table[CNT_DATA][fivetuples] += (uint64_t)(payload_size);
		flow_current_size_table[CNT_DATA][fivetuples] += (uint64_t)(payload_size);
		flow_packet_num_table[CNT_DATA][fivetuples] += 1;	
		// // !临时测试
		// std::cout << p->GetSize() << '\t' << ch.m_headerSize << '\t' << ch.GetSerializedSize() << '\n';
		//当前数据包是当前流上的第一个数据包（上行），则更新流第一个数据包的抵达时间，初始化最大包大小，最小包大小，当前burst等信息
		if(flow_first_pkt_time_table[CNT_DATA].find(fivetuples) == flow_first_pkt_time_table[CNT_DATA].end())
		{
			//第一个数据包抵达时间以及上一个数据包抵达时间
			flow_first_pkt_time_table[CNT_DATA][fivetuples] = current_time;
			flow_last_pkt_time_table[CNT_DATA][fivetuples] = current_time;
			//初始化平均包大小，最大包大小、最小包大小特征
			flow_max_pkt_size_table[CNT_DATA][fivetuples] = (uint64_t)(payload_size);
			flow_min_pkt_size_table[CNT_DATA][fivetuples] = (uint64_t)(payload_size);
			flow_avg_pkt_size_table[CNT_DATA][fivetuples] = (uint64_t)(payload_size);
			flow_gap_pkt_size_table[CNT_DATA][fivetuples] = 0;
			//初始化最大包到达间隔，最小包到达间隔，平均包到达间隔
			flow_max_pkt_interval_table[CNT_DATA][fivetuples] = 0.0;
			flow_min_pkt_interval_table[CNT_DATA][fivetuples] = 1000000000;
			flow_avg_pkt_interval_table[CNT_DATA][fivetuples] - 0.0;
			//初始化平均burst
			flow_current_burst_size_table[CNT_DATA][fivetuples] += (uint64_t)(payload_size);
			flow_max_burst_size_table[CNT_DATA][fivetuples] = 0;
			flow_total_burst_size_table[CNT_DATA][fivetuples] = 0;
			flow_avg_burst_size_table[CNT_DATA][fivetuples] = 0;
			flow_burst_num_table[CNT_DATA][fivetuples] = 0;
			//初始化流速率特征
			flow_speed_table[CNT_DATA][fivetuples] = 0.0;

			// *针对流判断优先级
			flow_pg_pktNum_table[0][fivetuples] = flow_pg_pktNum_table[1][fivetuples] = flow_pg_pktNum_table[2][fivetuples] = 0;
			// *针对老化初始化
			flow_idle_num_table[CNT_DATA][fivetuples] = 0;
			flow_current_frate_table[CNT_DATA][fivetuples] = 0;

			// * 新增qp对映射环节

		}
		//若不是第一个数据包，则需要开始计算pkt_interval相关的特征信息并进行其他特征的更新
		else
		{
			//计算包间隔，更新上一个数据包抵达时间
			double pkt_interval = (current_time - flow_last_pkt_time_table[CNT_DATA][fivetuples]);
			flow_last_pkt_time_table[CNT_DATA][fivetuples] = current_time;
			//更新平均包大小，最大包大小、最小包大小特征
			flow_max_pkt_size_table[CNT_DATA][fivetuples] = std::max((uint64_t)flow_max_pkt_size_table[CNT_DATA][fivetuples], (uint64_t)(payload_size));
			flow_min_pkt_size_table[CNT_DATA][fivetuples] = std::min((uint64_t)flow_min_pkt_size_table[CNT_DATA][fivetuples],(uint64_t)(payload_size));
			flow_avg_pkt_size_table[CNT_DATA][fivetuples] = flow_byte_size_table[CNT_DATA][fivetuples] / flow_packet_num_table[CNT_DATA][fivetuples];
			flow_gap_pkt_size_table[CNT_DATA][fivetuples] = flow_max_pkt_size_table[CNT_DATA][fivetuples] - flow_min_pkt_size_table[CNT_DATA][fivetuples];
			//更新化最大包到达间隔，最小包到达间隔, 平均包到达间隔
			flow_max_pkt_interval_table[CNT_DATA][fivetuples] = std::max((double)flow_max_pkt_interval_table[CNT_DATA][fivetuples], pkt_interval);
			flow_min_pkt_interval_table[CNT_DATA][fivetuples] = std::min((double)flow_min_pkt_interval_table[CNT_DATA][fivetuples], pkt_interval);
			flow_avg_pkt_interval_table[CNT_DATA][fivetuples] = (flow_last_pkt_time_table[CNT_DATA][fivetuples] - flow_first_pkt_time_table[CNT_DATA][fivetuples]) / flow_packet_num_table[CNT_DATA][fivetuples];
			//更新流速率
			flow_speed_table[CNT_DATA][fivetuples] = (double)(flow_byte_size_table[CNT_DATA][fivetuples]) / ((flow_last_pkt_time_table[CNT_DATA][fivetuples] - flow_first_pkt_time_table[CNT_DATA][fivetuples]));
			//更新burst
			//当前数据包间隔小于burst duration，那么继续更新current burst
			if(pkt_interval < burst_max_duration)
			{
				flow_current_burst_size_table[CNT_DATA][fivetuples] += (uint64_t)(payload_size);
			}
			//当前burst结束，更新全局burst特征信息
			else
			{
				flow_max_burst_size_table[CNT_DATA][fivetuples] = std::max((uint64_t)flow_max_burst_size_table[CNT_DATA][fivetuples], (uint64_t)flow_current_burst_size_table[CNT_DATA][fivetuples]);
				flow_total_burst_size_table[CNT_DATA][fivetuples] += flow_current_burst_size_table[CNT_DATA][fivetuples];
				flow_burst_num_table[CNT_DATA][fivetuples] += 1;
				flow_avg_burst_size_table[CNT_DATA][fivetuples] = flow_total_burst_size_table[CNT_DATA][fivetuples] / flow_burst_num_table[CNT_DATA][fivetuples];
				flow_current_burst_size_table[CNT_DATA][fivetuples] = (uint64_t)(payload_size);
			}

			// *针对流判断优先级;需要有优先级才能判断
			// !后续同样可以考虑创建缓冲区并迁移至周期一次的Switch_FlowPrinter()判断中，提高效率
		}

		if (flow_pg_class_table[CNT_DATA].find(fivetuples) != flow_pg_class_table[CNT_DATA].end())
			flow_pg_pktNum_table[flow_pg_class_table[CNT_DATA][fivetuples]-1][fivetuples] += 1;
		else
			flow_pg_pktNum_table[0][fivetuples] += 1;

		// !分类只做大小流分流
		// TODO: 一定要弄清是CNT还是OLD!!
		// if (flow_pg_class_table[])

		// *设置优先级
		// *PLAN A: 5(BEST!)
		// if (flow_max_pkt_size_table[CNT_DATA][fivetuples] <= 1369.5 &&
		// 	flow_avg_burst_size_table[CNT_DATA][fivetuples] <=6790.036 &&
		// 	flow_avg_pkt_interval_table[CNT_DATA][fivetuples] <= 0.568 &&
		// 	flow_avg_burst_size_table[CNT_DATA][fivetuples] > 78.0)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;

		// // *PLAN A(ver 2): 5
		// if (flow_max_pkt_size_table[CNT_DATA][fivetuples] <= 1369.5 &&
		// 	flow_min_pkt_size_table[CNT_DATA][fivetuples] <= 218.5 &&
		// 	flow_avg_pkt_interval_table[CNT_DATA][fivetuples] >0.004 &&
		// 	flow_avg_burst_size_table[CNT_DATA][fivetuples] > 80.621)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;

		// // *PLAN B: 4
		// if (flow_max_pkt_size_table[CNT_DATA][fivetuples] <= 0.576)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else if (flow_avg_burst_size_table[CNT_DATA][fivetuples] <= 257.008 &&
		// 		 flow_min_pkt_size_table[CNT_DATA][fivetuples] <=54.5)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;

		// // // *PLAN C: 4
		// if (flow_max_pkt_size_table[CNT_DATA][fivetuples] <= 0.611)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else if (flow_avg_pkt_size_table[CNT_DATA][fivetuples] <= 257.008 &&
		// 		 flow_avg_pkt_size_table[CNT_DATA][fivetuples] > 138.572)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;

		// // !PLAN D: 2(useless)
		// if (flow_avg_pkt_interval_table[CNT_DATA][fivetuples] <= 0.588)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;
		
		// // *PLAN E: 5(looks bad)
		// if (flow_max_pkt_interval_table[CNT_DATA][fivetuples] <= 0.588)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else if (flow_avg_burst_size_table[CNT_DATA][fivetuples] <= 212.652)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else if (flow_avg_pkt_size_table[CNT_DATA][fivetuples] <= 257.008 &&
		// 		 flow_min_pkt_size_table[CNT_DATA][fivetuples] <= 54.5)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;

		// // *PLAN F: 4(use train_feature, not train_feature2)
		// if (flow_avg_pkt_size_table[CNT_DATA][fivetuples] <= 749.358 &&
		// 	flow_avg_pkt_interval_table[CNT_DATA][fivetuples] <= 0.337 &&
		// 	flow_max_pkt_interval_table[CNT_DATA][fivetuples] <= 7.785)
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 1;
		// else
		// 	flow_pg_class_table[CNT_DATA][fivetuples] = 2;

		return;
	}
	//3s 300s调用一次 kill
	void printPriority() {
		//输出到文件打印（unordered_map）
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
		double TPCount[3];

		std::vector< std::pair<std::string, uint64_t> >	tmp_vec;
		
		std::cout << "\n\n";
		std::cout << "PktClass: High\n";
		tmpCount = 0;
		tmp_vec = {};
		for (auto& iter : flow_first_pkt_time_table[CNT_DATA])
		{
			auto udp_key = iter.first;
			// // !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
			// if (flow_max_pkt_size_table[CNT_DATA][udp_key] == 0.0) continue;
			// !流量限额减少后回传包载荷不为0，需要新的判别方式
			// !非常关键的改动
			if (udp_key.substr(0, 7) == "11:0:41") continue;

			if (flow_pg_class_table[CNT_DATA][udp_key] == 1)
			{
				tmp_vec.push_back({udp_key, flow_byte_size_table[CNT_DATA][udp_key]});
				tmpCount++;
			}
		}
		TPCount[0] = 0;
		TPCount[1] = 0;
		TPCount[2] = 0;
		std::cout << "Total: " << tmpCount << '\n';
		for (auto iter : tmp_vec)
		{
			auto totalPktNum = flow_pg_pktNum_table[0][iter.first] + flow_pg_pktNum_table[1][iter.first] + flow_pg_pktNum_table[2][iter.first];
			std::cout << "\tid: " << iter.first << "\tsize: " << iter.second << '\n';
			std::cout << "\t" << "1: " << flow_pg_pktNum_table[0][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[0][iter.first] << '\n';
			std::cout << "\t" << "2: " << flow_pg_pktNum_table[1][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[1][iter.first] << '\n';
			std::cout << "\t" << "3: " << flow_pg_pktNum_table[2][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[2][iter.first] << '\n';
			std::cout << "\t" << "origin pg: " << origin_pg[iter.first] << '\n';

			if (origin_pg[iter.first] == 1)				TPCount[0]++;
			else if (origin_pg[iter.first] == 2)		TPCount[1]++;
			else if (origin_pg[iter.first] == 3)		TPCount[2]++;
		}
		std::cout << "\'\'\'\'Percentage: " << TPCount[0]/tmp_vec.size() << ':' \
											<< TPCount[1]/tmp_vec.size() << ':' \
											<< TPCount[2]/tmp_vec.size() << ':' \
											<< "\'\'\'\'\n";
		
		std::cout << "\n\n";
		std::cout << "PktClass: mid\n";
		tmpCount = 0;
		tmp_vec = {};
		for (auto& iter : flow_first_pkt_time_table[CNT_DATA])
		{
			auto udp_key = iter.first;
			// // !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
			// if (flow_max_pkt_size_table[CNT_DATA][udp_key] == 0.0) continue;
			// !流量限额减少后回传包载荷不为0，需要新的判别方式
			// !非常关键的改动
			if (udp_key.substr(0, 7) == "11:0:41") continue;

			if (flow_pg_class_table[CNT_DATA][udp_key] == 2)
			{
				tmp_vec.push_back({udp_key, flow_byte_size_table[CNT_DATA][udp_key]});
				tmpCount++;
			}
		}
		TPCount[0] = 0;
		TPCount[1] = 0;
		TPCount[2] = 0;
		std::cout << "Total: " << tmpCount << '\n';
		for (auto iter : tmp_vec)
		{
			auto totalPktNum = flow_pg_pktNum_table[0][iter.first] + flow_pg_pktNum_table[1][iter.first] + flow_pg_pktNum_table[2][iter.first];
			std::cout << "\tid: " << iter.first << "\tsize: " << iter.second << '\n';
			std::cout << "\t" << "1: " << flow_pg_pktNum_table[0][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[0][iter.first] << '\n';
			std::cout << "\t" << "2: " << flow_pg_pktNum_table[1][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[1][iter.first] << '\n';
			std::cout << "\t" << "3: " << flow_pg_pktNum_table[2][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[2][iter.first] << '\n';
			std::cout << "\t" << "origin pg: " << origin_pg[iter.first] << '\n';

			if (origin_pg[iter.first] == 1)				TPCount[0]++;
			else if (origin_pg[iter.first] == 2)		TPCount[1]++;
			else if (origin_pg[iter.first] == 3)		TPCount[2]++;
		}
		std::cout << "\'\'\'\'Percentage: " << TPCount[0]/tmp_vec.size() << ':' \
											<< TPCount[1]/tmp_vec.size() << ':' \
											<< TPCount[2]/tmp_vec.size() << ':' \
											<< "\'\'\'\'\n";


		std::cout << "\n\n";
		std::cout << "PktClass: low\n";
		tmpCount = 0;
		tmp_vec = {};
		for (auto& iter : flow_first_pkt_time_table[CNT_DATA])
		{
			auto udp_key = iter.first;
			// // !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
			// if (flow_max_pkt_size_table[CNT_DATA][udp_key] == 0.0) continue;
			// !流量限额减少后回传包载荷不为0，需要新的判别方式
			// !非常关键的改动
			if (udp_key.substr(0, 7) == "11:0:41") continue;

			if (flow_pg_class_table[CNT_DATA][udp_key] == 3)
			{
				tmp_vec.push_back({udp_key, flow_byte_size_table[CNT_DATA][udp_key]});
				tmpCount++;
			}
		}
		TPCount[0] = 0;
		TPCount[1] = 0;
		TPCount[2] = 0;
		std::cout << "Total: " << tmpCount << '\n';
		for (auto iter : tmp_vec)
		{
			auto totalPktNum = flow_pg_pktNum_table[0][iter.first] + flow_pg_pktNum_table[1][iter.first] + flow_pg_pktNum_table[2][iter.first];
			std::cout << "\tid: " << iter.first << "\tsize: " << iter.second << '\n';
			std::cout << "\t" << "1: " << flow_pg_pktNum_table[0][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[0][iter.first] << '\n';
			std::cout << "\t" << "2: " << flow_pg_pktNum_table[1][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[1][iter.first] << '\n';
			std::cout << "\t" << "3: " << flow_pg_pktNum_table[2][iter.first]/totalPktNum << '\t' <<  flow_pg_pktNum_table[2][iter.first] << '\n';
			std::cout << "\t" << "origin pg: " << origin_pg[iter.first] << '\n';

			if (origin_pg[iter.first] == 1)				TPCount[0]++;
			else if (origin_pg[iter.first] == 2)		TPCount[1]++;
			else if (origin_pg[iter.first] == 3)		TPCount[2]++;
		}
		std::cout << "\'\'\'\'Percentage: " << TPCount[0]/tmp_vec.size() << ':' \
											<< TPCount[1]/tmp_vec.size() << ':' \
											<< TPCount[2]/tmp_vec.size() << ':' \
											<< "\'\'\'\'\n";
		
		double finalPercentage[3][3] = {};
		for (auto& iter : flow_first_pkt_time_table[CNT_DATA])
		{
			auto udp_key = iter.first;
			// // !这一步将会跳过ACK与NACK（因为它们没有payload大小,若特征用Getsize()统计则有Header的大小）
			if (flow_max_pkt_size_table[CNT_DATA][udp_key] == 0.0) continue;
			auto totalPktNum = flow_pg_pktNum_table[0][iter.first] + flow_pg_pktNum_table[1][iter.first] + flow_pg_pktNum_table[2][iter.first];
			if (origin_pg[udp_key] == 1)
			{
				finalPercentage[0][0] += flow_pg_pktNum_table[0][iter.first]/totalPktNum;
				finalPercentage[0][1] += flow_pg_pktNum_table[1][iter.first]/totalPktNum;
				finalPercentage[0][2] += flow_pg_pktNum_table[2][iter.first]/totalPktNum;
			}
			else if (origin_pg[udp_key] == 2)
			{
				finalPercentage[1][0] += flow_pg_pktNum_table[0][iter.first]/totalPktNum;
				finalPercentage[1][1] += flow_pg_pktNum_table[1][iter.first]/totalPktNum;
				finalPercentage[1][2] += flow_pg_pktNum_table[2][iter.first]/totalPktNum;
			}
			else if (origin_pg[udp_key] == 3)
			{
				finalPercentage[2][0] += flow_pg_pktNum_table[0][iter.first]/totalPktNum;
				finalPercentage[2][1] += flow_pg_pktNum_table[1][iter.first]/totalPktNum;
				finalPercentage[2][2] += flow_pg_pktNum_table[2][iter.first]/totalPktNum;
			}
		}

		const uint32_t HIGH_NUM = 135;
		const uint32_t MIDDLE_NUM = 30;
		const uint32_t LOW_NUM = 135;

		std::cout << "final_acc_Percentage: \n";
		std::cout << "\t" << "1: \t" << finalPercentage[0][0]/HIGH_NUM << '\t' <<  \
										finalPercentage[0][1]/HIGH_NUM << '\t' <<  \
										finalPercentage[0][2]/HIGH_NUM << '\n';
		std::cout << "\t" << "2: \t" << finalPercentage[1][0]/MIDDLE_NUM << '\t' <<  \
										finalPercentage[1][1]/MIDDLE_NUM << '\t' <<  \
										finalPercentage[1][2]/MIDDLE_NUM << '\n';
		std::cout << "\t" << "3: \t" << finalPercentage[2][0]/LOW_NUM << '\t' <<  \
										finalPercentage[2][1]/LOW_NUM << '\t' <<  \
										finalPercentage[2][2]/LOW_NUM << '\n';
	}


	/**
	 * @brief 改用pias的形式
	 * 
	 */
	void SwitchNode::Switch_FlowPrinter()
	{
		static uint32_t CallNum = 0;
		bool Canout = (CallNum%1000 == 0);
		if (Canout) std::cout << '\n';
		
		// for (auto& tb : flow_byte_size_table[OLD_DATA])
		// {
		// 	// !还是那个问题：不要考虑回传的ACK（否则数目会*2）
		// 	if (tb.second == 0.0) continue;

		// 	if (TOP_20percent.renew(tb.first, tb.second) == false)
		// 		TOP_20percent.push({tb.first, tb.second});
		// 	// if (Canout) std::cout << "load: ";
		// 	// if (Canout) std::cout << "\tid: " << tb.first << "\tsize: " << tb.second << '\n';
		// }

		// !注意用OLD的数据计算CNT的优先级
		if (Canout) std::cout << "Round: " << CallNum << '\n';
		std::vector< std::pair<std::string, uint32_t> > tmpFlowlist[3];
		std::vector<std::string> tmpDellist;

		// *PIAS方式区分优先级
		for (auto& tb:flow_byte_size_table[CNT_DATA])
		{
			// !流量限额减少后回传包载荷不为0，需要新的判别方式
			// !非常关键的改动

			// if (tb.second == 0.0) continue;
			if (tb.first.substr(0, 7) == "11:0:41") continue;
			
			std::string key = tb.first;
			uint32_t val = tb.second;
			if (tb.second <= 16*1024)
			{
				flow_pg_class_table[CNT_DATA][key] = 1;
				tmpFlowlist[0].push_back({key, val});

				flow_current_frate_table[CNT_DATA][key] = 	AGING_ALPHA_SMALL * flow_current_frate_table[CNT_DATA][key]  + \
															(1-AGING_ALPHA_SMALL) * flow_speed_table[CNT_DATA][key];
				if (flow_current_frate_table[CNT_DATA][key] < SIZE_IDLE_THRESHOLD)
					flow_idle_num_table[CNT_DATA][key]++;
				if (flow_idle_num_table[CNT_DATA][key] >= PERIOD_IDLE_THRESHOLD)
					tmpDellist.push_back(key);
			}
			else if (tb.second <= 896*1024)
			{
				flow_pg_class_table[CNT_DATA][key] = 2;
				tmpFlowlist[1].push_back({key, val});

				flow_current_frate_table[CNT_DATA][key] = 	AGING_ALPHA_BIG * flow_current_frate_table[CNT_DATA][key]  + \
															(1-AGING_ALPHA_BIG) * flow_speed_table[CNT_DATA][key];
				if (flow_current_frate_table[CNT_DATA][key] < SIZE_IDLE_THRESHOLD)
					flow_idle_num_table[CNT_DATA][key]++;
				if (flow_idle_num_table[CNT_DATA][key] >= PERIOD_IDLE_THRESHOLD)
					tmpDellist.push_back(key);
			}
			else
			{
				flow_pg_class_table[CNT_DATA][key] = 3;
				tmpFlowlist[2].push_back({key, val});

				flow_current_frate_table[CNT_DATA][key] = 	AGING_ALPHA_BIG * flow_current_frate_table[CNT_DATA][key]  + \
															(1-AGING_ALPHA_BIG) * flow_speed_table[CNT_DATA][key];
				if (flow_current_frate_table[CNT_DATA][key] < SIZE_IDLE_THRESHOLD)
					flow_idle_num_table[CNT_DATA][key]++;
				if (flow_idle_num_table[CNT_DATA][key] >= PERIOD_IDLE_THRESHOLD)
					tmpDellist.push_back(key);
			}
		}


		// if (Canout) std::cout << "High class: " << TOP_20percent.Top.size() <<'\n';
// 		for (auto& node : TOP_20percent.Top.vec)
// 		{
// 			// if (Canout) std::cout << "\tid: " << node.key << "\tsize: " << node.val << '\n';
		
// 			flow_pg_class_table[CNT_DATA][node.key] = 1;
// 			tmpFlowlist[0].push_back({node.key, node.val});

// 			flow_current_frate_table[CNT_DATA][node.key] = 	AGING_ALPHA_SMALL * flow_current_frate_table[CNT_DATA][node.key]  + \
// 															(1-AGING_ALPHA_SMALL) * flow_speed_table[CNT_DATA][node.key];
// 			if (flow_current_frate_table[CNT_DATA][node.key] < SIZE_IDLE_THRESHOLD)
// 				flow_idle_num_table[CNT_DATA][node.key]++;
// 			if (flow_idle_num_table[CNT_DATA][node.key] >= PERIOD_IDLE_THRESHOLD)
// 				tmpDellist.push_back(node.key);

// 			// !注意及时将周期流表清空!
// 			flow_current_frate_table[CNT_DATA][node.key] = 0;

// 		}

// 		// if (Canout) std::cout << "low class: " << TOP_20percent.Bottom.size() <<'\n';
// 		for (auto& node : TOP_20percent.Bottom.vec)
// 		{
// 			// if (Canout) std::cout << "\tid: " << node.key << "\tsize: " << node.val << '\n';
// 			// !注意用OLD的数据计算CNT的优先级
// 			// flow_pg_class_table[CNT_DATA][node.key] = 2;

// 			// *PLAN A: 5(BEST!)
// 			// if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 1369.5 &&
// 			// 	flow_avg_burst_size_table[CNT_DATA][node.key] <=6790.036 &&
// 			// 	flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.568 &&
// 			// 	flow_avg_burst_size_table[CNT_DATA][node.key] > 78.0)
// 			// {	
// 			// 	flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 	tmpFlowlist[1].push_back({node.key, node.val});
// 			// }			
// 			// else
// 			// {	
// 			// 	flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 	tmpFlowlist[2].push_back({node.key, node.val});
// 			// }

// 			// *PLAN G: 6(have a try!)
// 			// if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 710.759)
// 			// {
// 			// 	if (flow_max_pkt_interval_table[CNT_DATA][node.key] <=1.012)
// 			// 	{
// 			// 		if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 20107.286)
// 			// 		{
// 			// 			if (flow_speed_table[CNT_DATA][node.key] <= 224.188)
// 			// 			{
// 			// 				if (flow_min_pkt_size_table[CNT_DATA][node.key] <= 91.0)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 			}
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.11)
// 			// 			{
// 			// 				if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.0)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 			}
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.068)
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 		else
// 			// 		{
// 			// 			if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 1379.5)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 		}
// 			// 	}
// 			// }
// 			// else
// 			// {
// 			// 	if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.053)
// 			// 	{
// 			// 		if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.0)
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		else
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 	}
// 			// 	else
// 			// 		flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// }

// 			// PLAN H
// 			// if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 745.683)
// 			// {
// 			// 	if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.012)
// 			// 	{
// 			// 		if (flow_speed_table[CNT_DATA][node.key] <= 96693.512)
// 			// 		{
// 			// 			if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 19740.933)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			else
// 			// 			{
// 			// 				if (flow_max_burst_size_table[CNT_DATA][node.key] <= 805656.5)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 1273.0)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.068)
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 		else
// 			// 		{
// 			// 			if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 1388.0)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 		}
// 			// 	}
// 			// }
// 			// else
// 			// 	flow_pg_class_table[CNT_DATA][node.key] = 3;

// 			// PLAN I: huge!!!!
// 			// if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 817.493)
// 			// {
// 			// 	if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.144)
// 			// 	{
// 			// 		if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 10.024)
// 			// 		{
// 			// 			if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 21045.681)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			else
// 			// 			{
// 			// 				if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.019)
// 			// 				{
// 			// 					if (flow_max_burst_size_table[CNT_DATA][node.key] <= 805656.5)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				}
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.0)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 239.761)
// 			// 		{
// 			// 			if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 30.065)
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.66)
// 			// 				{
// 			// 					if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 140.942)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 30.058)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 30.093)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_min_pkt_size_table[CNT_DATA][node.key] <= 309.5)
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.884)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				else
// 			// 				{
// 			// 					if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 30.053)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.308)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 		}
// 			// 	}
// 			// }
// 			// else
// 			// {
// 			// 	if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.053)
// 			// 	{
// 			// 		if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 950.288)
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 		else
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 	}
// 			// 	else
// 			// 		flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// }
		
// 			// PLAN J: also huge....
// 			// if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 817.493)
// 			// {
// 			// 	if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.144)
// 			// 	{
// 			// 		if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 10.024)
// 			// 		{
// 			// 			if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 21045.681)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			else
// 			// 			{
// 			// 				if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.019)
// 			// 				{
// 			// 					if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 97.082)
// 			// 					{
// 			// 						if (flow_speed_table[CNT_DATA][node.key] <= 4877.312)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					}
// 			// 					else
// 			// 					{
// 			// 						if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.059)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 					}
// 			// 				}
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.0)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 239.761)
// 			// 		{
// 			// 			if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <=30.065)
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.66)
// 			// 				{
// 			// 					if (flow_max_burst_size_table[CNT_DATA][node.key] <= 3032.0)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 				else
// 			// 				{
// 			// 					if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 30.014)
// 			// 					{
// 			// 						if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 5.0)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					}
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 30.093)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 210.797)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 					{
// 			// 						if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 225.946)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					}
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_min_pkt_size_table[CNT_DATA][node.key] <= 309.5)
// 			// 			{
// 			// 				if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 30.053)
// 			// 				{
// 			// 					if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.884)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.0)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				else
// 			// 				{
// 			// 					if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.03)
// 			// 					{
// 			// 						if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 712.585)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					}
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 	}
// 			// }
// 			// else
// 			// {
// 			// 	if (flow_max_burst_size_table[CNT_DATA][node.key] <= 1479.5)
// 			// 	{
// 			// 		if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.013)
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		else
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 	}
// 			// 	else
// 			// 		flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// }

// 			// // PLAN K
// 			// if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 817.493)
// 			// {
// 			// 	if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.144)
// 			// 	{
// 			// 		if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 10.024)
// 			// 		{
// 			// 			if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 21045.681)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			else
// 			// 			{
// 			// 				if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.019)
// 			// 				{
// 			// 					if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 97.082)
// 			// 					{
// 			// 						if (flow_speed_table[CNT_DATA][node.key] <= 4877.312)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					}
// 			// 					else
// 			// 					{
// 			// 						if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.059)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 					}
// 			// 				}
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.0)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 239.761)
// 			// 		{
// 			// 			if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 30.065)
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.66)
// 			// 				{
// 			// 					// !以下一句判断为false仅有1个样本；可考虑后续剪枝
// 			// 					if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 140.942)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 				else
// 			// 				{
// 			// 					if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 30.014)
// 			// 					{
// 			// 						if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 5.0)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					}
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 30.093)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_burst_size_table[CNT_DATA][node.key] > 201.797 && \
// 			// 						flow_avg_burst_size_table[CNT_DATA][node.key] <= 255.946)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 9.647)
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.884)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				else
// 			// 				{
// 			// 					if (flow_speed_table[CNT_DATA][node.key] > 1148.687 && \
// 			// 						flow_min_pkt_interval_table[CNT_DATA][node.key] >0.016)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_speed_table[CNT_DATA][node.key] <= 8.301)
// 			// 				{
// 			// 					if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 5413118)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 				}
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 507.24 && \
// 			// 						flow_max_pkt_interval_table[CNT_DATA][node.key] <= 437.66)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 	}
// 			// }
// 			// else
// 			// {	
// 			// 	// !同前：仅有1个样本优先级为2，可考虑剪枝
// 			// 	if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.053 && \
// 			// 		flow_avg_pkt_size_table[CNT_DATA][node.key] > 950.288)
// 			// 		flow_pg_class_table[CNT_DATA][node.key] = 2;
// 			// 	else
// 			// 		flow_pg_class_table[CNT_DATA][node.key] = 3;
// 			// }

// 			// #define VOICE 		2
// 			// #define VMEETING 	2
// 			// #define GAME		2
// 			// #define FILE		3
// 			// #define VOD			3

// 			// !截至2024.1均采用该版本(应该标为PLAN L)
// 			// // plan K: 5 class
// 			// if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 562.5)
// 			// {
// 			// 	if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.061)
// 			// 	{
// 			// 		if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.028)
// 			// 		{
// 			// 			if (flow_max_burst_size_table[CNT_DATA][node.key] <= 5533.0)
// 			// 			{
// 			// 				if (flow_max_burst_size_table[CNT_DATA][node.key] <= 945.0)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 				else
// 			// 				{
// 			// 					if (flow_max_burst_size_table[CNT_DATA][node.key] <= 1546.5)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// 			// 					else
// 			// 					{
// 			// 						if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.019)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// 			// 					}
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_min_pkt_interval_table[CNT_DATA][node.key] <= 68.0)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.019)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 92.496)
// 			// 			{
// 			// 				if (flow_max_burst_size_table[CNT_DATA][node.key] <= 956.5)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = GAME;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// 			// 			}
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = GAME;
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 2.264)
// 			// 		{
// 			// 			if (flow_max_burst_size_table[CNT_DATA][node.key] <= 212.0)
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.656)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 1.06 && \
// 			// 						flow_avg_burst_size_table[CNT_DATA][node.key] <= 90.0)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.012)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_speed_table[CNT_DATA][node.key] <= 304.515)
// 			// 			{
// 			// 				if (flow_min_pkt_size_table[CNT_DATA][node.key] <= 38.5)
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 				else
// 			// 				{
// 			// 					if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 301.012)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 		}
// 			// 	}
// 			// }
// 			// else
// 			// {
// 			// 	if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 1388.0)
// 			// 	{
// 			// 		if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 2599.17)
// 			// 		{
// 			// 			if (flow_speed_table[CNT_DATA][node.key] <= 1130.516)
// 			// 			{
// 			// 				if (flow_max_burst_size_table[CNT_DATA][node.key] <= 3032.0)
// 			// 				{
// 			// 					if (flow_avg_burst_size_table[CNT_DATA][node.key] <= 96.175)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 				}
// 			// 				else
// 			// 					flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 			}
// 			// 			else
// 			// 			{
// 			// 				if (flow_max_pkt_size_table[CNT_DATA][node.key] <= 1396.5)
// 			// 				{
// 			// 					if (flow_min_pkt_size_table[CNT_DATA][node.key] > 82.5 && \
// 			// 						flow_avg_pkt_size_table[CNT_DATA][node.key] <= 364.498)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// 			// 				}
// 			// 				else
// 			// 				{
// 			// 					if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.029)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 		else
// 			// 		{
// 			// 			if (flow_avg_pkt_size_table[CNT_DATA][node.key] <= 617.542)
// 			// 			{
// 			// 				if (flow_speed_table[CNT_DATA][node.key] <= 13221.144)
// 			// 				{
// 			// 					if (flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.409)
// 			// 					{
// 			// 						if (flow_max_burst_size_table[CNT_DATA][node.key] <= 805656.5)
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 						else
// 			// 							flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// 			// 					}
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 				}
// 			// 				else
// 			// 				{
// 			// 					if (flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 599.864)
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 					else
// 			// 						flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// 			// 				}
// 			// 			}
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 		}
// 			// 	}
// 			// 	else
// 			// 	{
// 			// 		if (flow_min_pkt_size_table[CNT_DATA][node.key] <= 52.5)
// 			// 		{
// 			// 			if (flow_min_pkt_size_table[CNT_DATA][node.key] > 48.5 && \
// 			// 				flow_max_pkt_size_table[CNT_DATA][node.key] <= 1479.0)
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = VOD;
// 			// 			else
// 			// 				flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 		}
// 			// 		else
// 			// 			flow_pg_class_table[CNT_DATA][node.key] = FILE;
// 			// 	}
// 			// }

// 			// plan L: new feature:gap_pkt_size
// // if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 520.50)
// //  if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 256.50)
// //   if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 3.51)
// //    if(flow_max_burst_size_table[CNT_DATA][node.key] <= 212.00)
// //     if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.66)
// //       flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //     else
// //      if(flow_speed_table[CNT_DATA][node.key] <= 45.40)
// //        flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //      else
// //       if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 90.00)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //    else
// //     if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 2430.67)
// //      if(flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.00)
// //       if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.03)
// //         flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = GAME;
// //      else
// //       if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.01)
// //         flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //     else
// //      if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.02)
// //       if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 22830.26)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //   else
// //    if(flow_speed_table[CNT_DATA][node.key] <= 2.53)
// //      flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //    else
// //     if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 2553.10)
// //      if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 5.00)
// //       if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 9.00)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //      else
// //       if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 15.01)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //  else
// //   if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.03)
// //    if(flow_max_burst_size_table[CNT_DATA][node.key] <= 5583.50)
// //     if(flow_speed_table[CNT_DATA][node.key] <= 8834.90)
// //      if(flow_max_burst_size_table[CNT_DATA][node.key] <= 2004.00)
// //       if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.08)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //      else
// //       if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.02)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //    else
// //     if(flow_max_burst_size_table[CNT_DATA][node.key] <= 8176.00)
// //       flow_pg_class_table[CNT_DATA][node.key] = GAME;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //   else
// //    if(flow_speed_table[CNT_DATA][node.key] <= 839.73)
// //     if(flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.19)
// //       flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //    else
// //     if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.04)
// //      if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 0.72)
// //        flow_pg_class_table[CNT_DATA][node.key] = GAME;
// //      else
// //       if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 122.26)
// //         flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = GAME;
// // else
// //  if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 1349.50)
// //   if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 2599.17)
// //    if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.02)
// //     if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 179.32)
// //       flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //    else
// //     if(flow_speed_table[CNT_DATA][node.key] <= 1130.52)
// //      if(flow_max_burst_size_table[CNT_DATA][node.key] <= 3032.00)
// //       if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 725.50)
// //         flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //     else
// //      if(flow_speed_table[CNT_DATA][node.key] <= 5866.14)
// //        flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //      else
// //       if(flow_max_burst_size_table[CNT_DATA][node.key] <= 1378.00)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //   else
// //    if(flow_max_burst_size_table[CNT_DATA][node.key] <= 33998.50)
// //     if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 853.00)
// //       flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //     else
// //       flow_pg_class_table[CNT_DATA][node.key] = VMEETING;
// //    else
// //     if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 961.00)
// //      if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.41)
// //       if(flow_max_burst_size_table[CNT_DATA][node.key] <= 805656.50)
// //         flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOICE;
// //      else
// //       if(flow_min_pkt_interval_table[CNT_DATA][node.key] <= 0.00)
// //         flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //       else
// //         flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //     else
// //      if(flow_max_burst_size_table[CNT_DATA][node.key] <= 48423.50)
// //        flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //  else
// //   if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 35.22)
// //    if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.01)
// //     if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 2.56)
// //      if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 1.71)
// //        flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //     else
// //      if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 16986.83)
// //        flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //    else
// //     if(flow_max_burst_size_table[CNT_DATA][node.key] <= 2568.50)
// //       flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //     else
// //      if(flow_avg_pkt_interval_table[CNT_DATA][node.key] <= 0.01)
// //        flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //   else
// //    if(flow_gap_pkt_size_table[CNT_DATA][node.key] <= 1419.00)
// //     if(flow_avg_burst_size_table[CNT_DATA][node.key] <= 5920.59)
// //       flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //     else
// //      if(flow_max_pkt_interval_table[CNT_DATA][node.key] <= 128.29)
// //        flow_pg_class_table[CNT_DATA][node.key] = VOD;
// //      else
// //        flow_pg_class_table[CNT_DATA][node.key] = FILE;
// //    else
// //      flow_pg_class_table[CNT_DATA][node.key] = VOD;


// 			if (flow_pg_class_table[CNT_DATA][node.key] == 2)			tmpFlowlist[1].push_back({node.key, node.val});
// 			else if (flow_pg_class_table[CNT_DATA][node.key] == 3)		tmpFlowlist[2].push_back({node.key, node.val});


// 			flow_current_frate_table[CNT_DATA][node.key] = 	AGING_ALPHA_BIG * flow_current_frate_table[CNT_DATA][node.key]  + \
// 															(1-AGING_ALPHA_BIG) * flow_speed_table[CNT_DATA][node.key];
// 			if (flow_current_frate_table[CNT_DATA][node.key] < SIZE_IDLE_THRESHOLD)
// 				flow_idle_num_table[CNT_DATA][node.key]++;
// 			if (flow_idle_num_table[CNT_DATA][node.key] >= PERIOD_IDLE_THRESHOLD)
// 				tmpDellist.push_back(node.key);
				
// 			// !注意及时将周期流表清空!
// 			flow_current_frate_table[CNT_DATA][node.key] = 0;
// 		}



		if (Canout) std::cout << "High class: " << tmpFlowlist[0].size() <<'\n';
		for (auto& iter : tmpFlowlist[0])
			if (Canout) std::cout << "\tid: " << iter.first << "\tsize: " << iter.second << '\n';
		if (Canout) std::cout << "Mid class: " << tmpFlowlist[1].size() <<'\n';
		for (auto& iter : tmpFlowlist[1])
			if (Canout) std::cout << "\tid: " << iter.first << "\tsize: " << iter.second << '\n';
		if (Canout) std::cout << "Low class: " << tmpFlowlist[2].size() <<'\n';
		for (auto& iter : tmpFlowlist[2])
			if (Canout) std::cout << "\tid: " << iter.first << "\tsize: " << iter.second << '\n';

		// if (Canout) std::cout << TOP_20percent.size() << ':' << TOP_20percent.Top.size() << ':' << TOP_20percent.Bottom.size() << '\n';


		// *老化更新流表
		for (auto& k : tmpDellist)
		{
			TOP_20percent.del(k);

			flow_byte_size_table[CNT_DATA].erase(k);
			flow_packet_num_table[CNT_DATA].erase(k);

			flow_last_pkt_time_table[CNT_DATA].erase(k);
			flow_first_pkt_time_table[CNT_DATA].erase(k);
			flow_min_pkt_interval_table[CNT_DATA].erase(k);
			flow_max_pkt_interval_table[CNT_DATA].erase(k);
			flow_avg_pkt_interval_table[CNT_DATA].erase(k);

			flow_max_pkt_size_table[CNT_DATA].erase(k);
			flow_min_pkt_size_table[CNT_DATA].erase(k);
			flow_avg_pkt_size_table[CNT_DATA].erase(k);
			flow_gap_pkt_size_table[CNT_DATA].erase(k);

			flow_current_burst_size_table[CNT_DATA].erase(k);
			flow_max_burst_size_table[CNT_DATA].erase(k);
			flow_avg_burst_size_table[CNT_DATA].erase(k);
			flow_total_burst_size_table[CNT_DATA].erase(k);
			flow_burst_num_table[CNT_DATA].erase(k);

			flow_speed_table[CNT_DATA].erase(k);
			flow_pg_class_table[CNT_DATA].erase(k);
		}

		// 打印优先级

		// 实际想把其作为一个锁来使用....
		index = 0;

		flow_byte_size_table[OLD_DATA] 				= flow_byte_size_table[CNT_DATA];
		flow_packet_num_table[OLD_DATA] 			= flow_packet_num_table[CNT_DATA];

		flow_last_pkt_time_table[OLD_DATA] 			= flow_last_pkt_time_table[CNT_DATA];
		flow_first_pkt_time_table[OLD_DATA] 		= flow_first_pkt_time_table[CNT_DATA];
		flow_min_pkt_interval_table[OLD_DATA] 		= flow_min_pkt_interval_table[CNT_DATA];
		flow_max_pkt_interval_table[OLD_DATA] 		= flow_max_pkt_interval_table[CNT_DATA];
		flow_avg_pkt_interval_table[OLD_DATA] 		= flow_avg_pkt_interval_table[CNT_DATA];

		flow_max_pkt_size_table[OLD_DATA] 			= flow_max_pkt_size_table[CNT_DATA];
		flow_min_pkt_size_table[OLD_DATA] 			= flow_min_pkt_size_table[CNT_DATA];
		flow_avg_pkt_size_table[OLD_DATA] 			= flow_avg_pkt_size_table[CNT_DATA];
		flow_gap_pkt_size_table[OLD_DATA]			= flow_gap_pkt_size_table[CNT_DATA];

		flow_current_burst_size_table[OLD_DATA] 	= flow_current_burst_size_table[CNT_DATA];
		flow_max_burst_size_table[OLD_DATA] 		= flow_max_burst_size_table[CNT_DATA];
		flow_avg_burst_size_table[OLD_DATA] 		= flow_avg_burst_size_table[CNT_DATA];
		flow_total_burst_size_table[OLD_DATA] 		= flow_total_burst_size_table[CNT_DATA];
		flow_burst_num_table[OLD_DATA] 				= flow_burst_num_table[CNT_DATA];

		flow_speed_table[OLD_DATA] 					= flow_speed_table[CNT_DATA];
		flow_pg_class_table[OLD_DATA] 				= flow_pg_class_table[CNT_DATA];

		index = 1;

		CallNum++;
		// if (Simulator::Now().GetSeconds() <= 15.0)
		// 	Simulator::Schedule(Seconds(0.2), &SwitchNode::Switch_FlowPrinter, this);
		// else
			Simulator::Schedule(Seconds(FlowPrinter_interval), &SwitchNode::Switch_FlowPrinter, this);
	}

	// 留作后续调度用：尚未声明
	// void SwitchNode::Switch_PktScheduler(){}


	// // 每间隔一定时间，调用的分类函数
	// typedef std::pair<std::string,uint32_t> flow_pair;
	// void FlowClassification() {
	// 	//切换读写的unordered_map
	// 	index = 1 - index;
	// 	//先做一个topK排序，将大流全部筛选出来
	// 	std::priority_queue<flow_pair,std::vector<flow_pair>,cmp> small_heap;
	//包抵达，特征都在更新，Simulator::Scheduler(time,FlowClassification);
	//
		// unordered_map<string,uint64_t> temp(flow_byte_size_table);
		// unordered_map<string,double> temp2(flow_avg_pkt_size_table);
		// //
		// topK(temp);
		// 小流 最高优先级
		// //先大小流分流 再细分大流优先级
		// 大流 中/低
		//小流筛出来
		//分类
	// 	//再对大流做优先级分类，存储到unordered_map当中
	// 	//这里存在一个设计细节上的问题，就是在完成所有unordered_map的载入前，应当还是采用上上一周期数据分类的结果，然后在当前周期再使用由上一周期计算出的结果
	// }

	void SwitchNode::load_OriginFlow_msg(Ipv4Address sip, Ipv4Address dip, uint16_t sport, uint16_t dport, uint8_t protocol, uint32_t pg)
	{
		auto ip2string = [](uint32_t ip)
		{
			return 	 std::to_string(ip>>24 & 0xff)+':'+std::to_string(ip>>16 & 0xff)+':'+std::to_string(ip>>8 & 0xff)+std::to_string(ip & 0xff);
		};
		std::string result = 	ip2string(sip.Get()) + " " + \
								ip2string(dip.Get()) + " " + \
								std::to_string(sport) + " " + \
								std::to_string(dport) + " " + \
								std::to_string(protocol);
		origin_pg[result] = pg;
	}

#endif

} /* namespace ns3 */
