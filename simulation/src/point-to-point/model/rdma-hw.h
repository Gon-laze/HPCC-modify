#ifndef RDMA_HW_H
#define RDMA_HW_H

#include <ns3/rdma.h>
#include <ns3/rdma-queue-pair.h>
#include <ns3/node.h>
#include <ns3/custom-header.h>
#include "qbb-net-device.h"
#include <unordered_map>
#include "pint.h"
#include <cstring>
#include <chrono>

namespace ns3 {

struct RdmaInterfaceMgr{
	//RdmaInterface包含两个属性，一个是指向QbbNetDevice类对象的Ptr，一个是指向RdmaQueuePairGroup类对象的Ptr
	Ptr<QbbNetDevice> dev;
	Ptr<RdmaQueuePairGroup> qpGrp;

	RdmaInterfaceMgr() : dev(NULL), qpGrp(NULL) {}
	RdmaInterfaceMgr(Ptr<QbbNetDevice> _dev){
		dev = _dev;
	}
};

class RdmaHw : public Object {
public:

	static TypeId GetTypeId (void);
	RdmaHw();

	Ptr<Node> m_node;	//所处节点的类型
	DataRate m_minRate;		//< Min sending rate 最小发送的速率
	uint32_t m_mtu;			//mtu，
	uint32_t m_cc_mode;		//网卡的CC控制模式
	double m_nack_interval;	//网卡NACK的间隔
	uint32_t m_chunk;	//网卡的块大小
	uint32_t m_ack_interval;	//网卡ACK的间隔
	bool m_backto0;	//Layer 2 go back to zero transmission.
	bool m_var_win, m_fast_react; //fast_react参数：拥塞的迅速反应相关 var_win参数：是否使用window size这一参数
	bool m_rateBound;	//网卡速率的上线
	std::vector<RdmaInterfaceMgr> m_nic; // list of running nic controlled by this RdmaHw //当前RDMA硬件所运行的RDMA网卡的list（虚拟化）
	std::unordered_map<uint64_t, Ptr<RdmaQueuePair> > m_qpMap; // mapping from uint64_t to qp	//从uint64_t映射到qp队列
	std::unordered_map<uint64_t, Ptr<RdmaRxQueuePair> > m_rxQpMap; // mapping from uint64_t to rx qp	//映射到rx qp队列
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	/******************************
	 * New Stats for rdma-hw.h
	 *****************************/
	//burst的最大包间隔，用于统计流量burst特征信息
	double burst_max_duration = 0.4;
	//所有的流表，其key均使用流五元组构成的字符串 TODO：重写哈希函数，构建key值为五元组的unordered_map
	//和包的总个数以及总字节数相关的统计table，
	std::unordered_map<string,uint64_t> flow_byte_size_table;
	std::unordered_map<string,uint64_t> flow_packet_num_table;
	//和包间隔相关的统计tables，包间隔特征：max_pkt_interval min_pkt_interval avg_pkt_interval
	std::unordered_map<string,std::chrono::system_clock::time_point> flow_last_pkt_time_table;
	std::unordered_map<string,std::chrono::system_clock::time_point> flow_first_pkt_time_table;
	std::unordered_map<string,double> flow_min_pkt_interval_table;
	std::unordered_map<string,double> flow_max_pkt_interval_table;
	std::unordered_map<string,double> flow_avg_pkt_interval_table;
	//和包大小相关的统计tables，包大小特征：max_pkt_size min_pkt_size avg_pkt_size
	std::unordered_map<string,uint16_t> flow_max_pkt_size_table;
	std::unordered_map<string,uint16_t> flow_min_pkt_size_table;
	std::unordered_map<string,uint16_t> flow_avg_pkt_size_table;
	//和burst相关的统计tables，burst特征：max_burst_size avg_burst_size
	std::unordered_map<string,uint64_t> flow_current_burst_size_table;
	std::unordered_map<string,uint64_t> flow_max_burst_size_table;
	std::unordered_map<string,uint64_t> flow_avg_burst_size_table;
	std::unordered_map<string,uint64_t> flow_total_burst_size_table;
	std::unordered_map<string,uint64_t> flow_burst_num_table;
	//和流速率相关的统计tables，flow speed
	std::unordered_map<string,double> flow_speed_table;

	//ECMP相关，从32位的ip地址映射到ECMP协议端口号（负载均衡相关）

	// qp complete callback
	//qp队列完成时对应的回调函数
	typedef Callback<void, Ptr<RdmaQueuePair> > QpCompleteCallback;
	QpCompleteCallback m_qpCompleteCallback;

	//设置网卡的node属性
	void SetNode(Ptr<Node> node);	
	//针对rmdahw上的所有rdma nic，设置它们的接收数据包/链路down掉/发送数据包的回调函数，并且在网卡层级共享rdmahw的数据信息
	void Setup(QpCompleteCallback cb); // setup shared data and callbacks with the QbbNetDevice
	//通过目的ip，源端口以及pg，获取查找对应qp的key值
	static uint64_t GetQpKey(uint32_t dip, uint16_t sport, uint16_t pg); // get the lookup key for m_qpMap
	//通过目的ip，源端口以及pg，获取查找对应的qp（返回对象为RdmaQueuePair）
	Ptr<RdmaQueuePair> GetQp(uint32_t dip, uint16_t sport, uint16_t pg); // get the qp
	//获取当前qp所在的NIC的index
	uint32_t GetNicIdxOfQp(Ptr<RdmaQueuePair> qp); // get the NIC index of the qp
	//添加queue pair，queue pair作用的对象是一个链接（srcip、dstip、dport以及sport确定），AddQueuePair会将qp绑定到一张虚拟网卡上，并添加到
	//Rdmahw下的unordered_map哈希表中，用一个key值标记该qp
	void AddQueuePair(uint64_t size, uint16_t pg, Ipv4Address _sip, Ipv4Address _dip, uint16_t _sport, uint16_t _dport, uint32_t win, uint64_t baseRtt, Callback<void> notifyAppFinish); // add a new qp (new send)
	//删除qp对，这里直接从unordered_map当中进行删除
	void DeleteQueuePair(Ptr<RdmaQueuePair> qp);
	//建立Rx对应的qp，create参数用于判断是否需要创建新qp
	Ptr<RdmaRxQueuePair> GetRxQp(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg, bool create); // get a rxQp
	//获取当前Rx qp所在的NIC的index
	uint32_t GetNicIdxOfRxQp(Ptr<RdmaRxQueuePair> q); // get the NIC index of the rxQp
	//删除Rx qp对，从对应的unordered_map当中进行删除
	void DeleteRxQp(uint32_t dip, uint16_t pg, uint16_t dport);

	//接收UDP数据包
	int ReceiveUdp(Ptr<Packet> p, CustomHeader &ch);
	//接收CNP数据包，CNP数据包主要用于拥塞控制，这里可以暂时无视该协议
	int ReceiveCnp(Ptr<Packet> p, CustomHeader &ch);
	//接收ACK数据包，同时处理了ACK数据包以及SACK数据包
	int ReceiveAck(Ptr<Packet> p, CustomHeader &ch); // handle both ACK and NACK
	//网卡在接收到数据包时，会选择调用对应的回调函数
	int Receive(Ptr<Packet> p, CustomHeader &ch); // callback function that the QbbNetDevice should use when receive packets. Only NIC can call this function. And do not call this upon PFC

	//TODO：未找到实现位置
	void CheckandSendQCN(Ptr<RdmaRxQueuePair> q);
	//TCP通信相关，用于check TCP header中的seqNo是否为期待值
	int ReceiverCheckSeq(uint32_t seq, Ptr<RdmaRxQueuePair> q, uint32_t size);
	//添加包头信息
	void AddHeader (Ptr<Packet> p, uint16_t protocolNumber);
	//将以太网的协议号转化为Ppp的协议号，这里的以太网协议为Ipv4以及Ipv6
	static uint16_t EtherToPpp (uint16_t protocol);

	//恢复qp对
	void RecoverQueue(Ptr<RdmaQueuePair> qp);
	//qp完成的处理函数（检测到应用程序完成时会调用删除qp的操作）
	void QpComplete(Ptr<RdmaQueuePair> qp);
	//关闭网络链接，这里是一个Rdmahw关闭，上面所有的虚拟网卡也会关闭
	void SetLinkDown(Ptr<QbbNetDevice> dev);

	// call this function after the NIC is setup
	//虚拟NIC被建立后，需要向rt_Table中添加表项，rt_Table使用data canter中的ECN技术，因此针对不同的目的ip会有不同的虚拟NIC与之对应
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	//清空rt_Tables
	void ClearTable();
	//重新在虚拟网卡群组上分配qp
	void RedistributeQp();

	//获取下一个需要发送的数据包，数据包的payload依赖于qp上的waitsend的字节数，该方法会生成一个packet对象，并返回
	Ptr<Packet> GetNxtPacket(Ptr<RdmaQueuePair> qp); // get next packet to send, inc snd_nxt
	//发送数据包，并更新下次可用的发包时间（控制发包速率）
	void PktSent(Ptr<RdmaQueuePair> qp, Ptr<Packet> pkt, Time interframeGap);
	//更新下次可用的发包时间
	void UpdateNextAvail(Ptr<RdmaQueuePair> qp, Time interframeGap, uint32_t pkt_size);
	//更改qp上的rate
	void ChangeRate(Ptr<RdmaQueuePair> qp, DataRate new_rate);
	/******************************
	 * Mellanox's version of DCQCN
	 *****************************/
	//决定rate减少程度的参数
	double m_g; //feedback weight
	//第一个CNP数据包的比率
	double m_rateOnFirstCNP; // the fraction of line rate to set on first CNP
	//ECN下的受限目标rate
	bool m_EcnClampTgtRate;
	//RP的速率增加定时器，以微秒为单位
	double m_rpgTimeReset;
	//rate减少的检测时间间隔
	double m_rateDecreaseInterval;
	//选择rate增长模式的依据（小于，等于，大于）
	uint32_t m_rpgThreshold;
	//恢复Alpha的时间间隔
	double m_alpha_resume_interval;
	//active-increase的增值
	DataRate m_rai;		//< Rate of additive increase
	//hyper-increase的增值
	DataRate m_rhai;		//< Rate of hyper-additive increase

	// the Mellanox's version of alpha update:
	// every fixed time slot, update alpha.
	//Mellanox 网卡上集成的DCQCN算法，这里相当于复现了该算法

	//更新Mellanox网卡的Alpha参数
	void UpdateAlphaMlx(Ptr<RdmaQueuePair> q);
	//定期更新Mellanox网卡上的参数，这里通过设置计时器调用Simulator::Schedule方法，并将该方法的参数设置为上面的UpdateAlphaMlx函数来实现
	void ScheduleUpdateAlphaMlx(Ptr<RdmaQueuePair> q);

	// Mellanox's version of CNP receive
	//Mellanox网卡版本的CNP包接收处理函数
	void cnp_received_mlx(Ptr<RdmaQueuePair> q);

	// Mellanox's version of rate decrease
	// It checks every m_rateDecreaseInterval if CNP arrived (m_decrease_cnp_arrived).
	// If so, decrease rate, and reset all rate increase related things
	//检查Mellanox网卡上Rate的减少情况
	void CheckRateDecreaseMlx(Ptr<RdmaQueuePair> q);
	////定期减小Mellanox网卡上的rate参数，这里通过设置计时器调用Simulator::Schedule方法，并将该方法的参数设置为上面的CheckDecreaseMlx函数来实现
	void ScheduleDecreaseRateMlx(Ptr<RdmaQueuePair> q, uint32_t delta);

	// Mellanox's version of rate increase
	void RateIncEventTimerMlx(Ptr<RdmaQueuePair> q);
	//根据increase的模式，选择对应的rate增加函数(从下面三个函数中选择)
	void RateIncEventMlx(Ptr<RdmaQueuePair> q);
	//快速恢复策略
	void FastRecoveryMlx(Ptr<RdmaQueuePair> q);
	//动态增长策略
	void ActiveIncreaseMlx(Ptr<RdmaQueuePair> q);
	//超量增加策略
	void HyperIncreaseMlx(Ptr<RdmaQueuePair> q);

	/***********************
	 * High Precision CC
	 ***********************/
	double m_targetUtil;
	double m_utilHigh;
	uint32_t m_miThresh;
	bool m_multipleRate;
	bool m_sampleFeedback; // only react to feedback every RTT, or qlen > 0
	//如果当前Rdmahw上的cc_mode为7，则在ReceiveACK当中会调用该处理函数（HPCC cc）
	void HandleAckHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);
	//update Rate的函数，在HPCC模式的处理函数HandleAckHPCC （上面的函数）中被调用，用于更新qp对上的rate
	void UpdateRateHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react);
	//TODO：看源代码，这个函数似乎未找到其实现
	void UpdateRateHpTest(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react);
	//FastReactHp内调用了UpdateRateHp函数，而该函数的调用位置是在HandleAckHp当中，即不调用UpdateRate时调用
	void FastReactHp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);

	/**********************
	 * TIMELY
	 *********************/
	double m_tmly_alpha, m_tmly_beta;
	uint64_t m_tmly_TLow, m_tmly_THigh, m_tmly_minRtt;
	//如果当前Rdmahw上的cc_mode为7，则在ReceiveACK当中会调用该处理函数（Timely cc）
	void HandleAckTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);
	//update Rate的函数，在Timely模式的处理函数HandleAckTimely（上面的函数）中被调用，用于更新qp对上的rate
	void UpdateRateTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool us);
	//TODO：看源代码，这个函数似乎未实现，是个空函数
	void FastReactTimely(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);

	/**********************
	 * DCTCP
	 *********************/
	DataRate m_dctcp_rai;
	//处理DCTCP的ACK数据包：DCTCP：在包头中附加额外信息用于标记当前路径上的交换机是否队列占用率超过一定阈值
	void HandleAckDctcp(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);

	/*********************
	 * HPCC-PINT
	 ********************/
	uint32_t pint_smpl_thresh;
	void SetPintSmplThresh(double p);
	//如果当前Rdmahw上的cc_mode为10，则在ReceiveACK当中会调用该处理函数（HPCC-PINT cc）
	void HandleAckHpPint(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch);
	//update Rate的函数，在HPCC-PINT模式的处理函数HandleAckHpPint（上面的函数）中被调用，用于更新qp对上的rate
	void UpdateRateHpPint(Ptr<RdmaQueuePair> qp, Ptr<Packet> p, CustomHeader &ch, bool fast_react);
};

} /* namespace ns3 */

#endif /* RDMA_HW_H */
