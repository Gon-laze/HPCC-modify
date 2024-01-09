/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* Copyright (c) 2006 Georgia Tech Research Corporation, INRIA
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation;
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef BROADCOM_EGRESS_H
#define BROADCOM_EGRESS_H

#include <queue>
#include "ns3/packet.h"
#include "queue.h"
#include "drop-tail-queue.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/event-id.h"

#ifndef MODIFY_ON
#define MODIFY_ON
#endif

namespace ns3 {

	class TraceContainer;

	class BEgressQueue : public Queue {
	public:
		static TypeId GetTypeId(void);
		static const unsigned fCnt = 128; //max number of queues, 128 for NICs
		static const unsigned qCnt = 8; //max number of queues, 8 for switches
		BEgressQueue();
		virtual ~BEgressQueue();
		bool Enqueue(Ptr<Packet> p, uint32_t qIndex);
		Ptr<Packet> DequeueRR(bool paused[]);
		uint32_t GetNBytes(uint32_t qIndex) const;
		uint32_t GetNBytesTotal() const;
		uint32_t GetLastQueue();

		#ifdef MODIFY_ON
			Ptr<Packet> Dequeue_QoS(bool paused[]);
			Ptr<Packet> Dequeue_QoS(bool paused[], void* args);
		#endif

		TracedCallback<Ptr<const Packet>, uint32_t> m_traceBeqEnqueue;
		TracedCallback<Ptr<const Packet>, uint32_t> m_traceBeqDequeue;

	private:
		bool DoEnqueue(Ptr<Packet> p, uint32_t qIndex);

		Ptr<Packet> DoDequeueRR(bool paused[]);
		#ifdef MODIFY_ON
			Ptr<Packet> DoDequeueSP(bool paused[]);
			Ptr<Packet> DoDequeueWRR(bool paused[]);
			Ptr<Packet> DoDequeueWFQ(bool paused[]);
			Ptr<Packet> DoDequeueIFC(bool paused[], double[]);

			// *仅针对WRR设置：每个优先级每轮的发包数目上限
			static const int WRR_MAXPNUM = 128;
			int WRR_token[qCnt + 1] = {};
			// *仅针对WRR设置：每个优先级每轮的发包大小上限
			static const int WFQ_MAXPNUM = 1024;
			int WFQ_token[qCnt + 1] = {};
			// *仅针对IFC设置：基于比例分配发包数目大小上限
			static const int IFC_MAXPNUM = 2048;
			int IFC_token[qCnt + 1] = {};
		#endif
		//for compatibility
		virtual bool DoEnqueue(Ptr<Packet> p);
		virtual Ptr<Packet> DoDequeue(void);
		virtual Ptr<const Packet> DoPeek(void) const;
		double m_maxBytes; //total bytes limit
		uint32_t m_bytesInQueue[fCnt];
		uint32_t m_bytesInQueueTotal;
		uint32_t m_rrlast;
		uint32_t m_qlast;
		std::vector<Ptr<Queue> > m_queues; // uc queues
	};

} // namespace ns3

#endif /* DROPTAIL_H */
