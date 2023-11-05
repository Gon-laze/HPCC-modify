/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007,2008,2009 INRIA, UDCAST
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
 *
 * Author: Amine Ismail <amine.ismail@sophia.inria.fr>
 *                      <amine.ismail@udcast.com>
 *
 */

#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#ifndef MODIFY_ON
#define MODIFY_ON

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"

#ifdef MODIFY_ON
  #ifndef _GLIBCXX_VECTOR
    #include <vector>
  #endif
#endif

// #ifndef DEBUG_ON
// #define DEBUG_ON

namespace ns3 {

class Socket;
class Packet;

/**
 * \ingroup udpclientserver
 * \class UdpClient
 * \brief A Udp client. Sends UDP packet carrying sequence number and time stamp
 *  in their payloads
 *
 */
class UdpClient : public Application
{
public:
  static TypeId
  GetTypeId (void);

  UdpClient ();

  virtual ~UdpClient ();

  /**
   * \brief set the remote address and port
   * \param ip remote IP address
   * \param port remote port
   */
  void SetRemote (Ipv4Address ip, uint16_t port);
  void SetRemote (Ipv6Address ip, uint16_t port);
  void SetRemote (Address ip, uint16_t port);
  void SetPG (uint16_t pg);

  #ifdef MODIFY_ON;
    std::fstream Custom_Packet_Info_File;
    const char CPIFName[] = "CPinfo.txt";
    bool is_CPIFinit = false;
    std::vector< std::pair<double, uint32_t> > PktInfo_vec;
    #ifdef DEBUG_ON;
      std::fstream Pkt_log;
      const char logName[] = "Pkt_log.txt";
      bool is_Loginit = false;
    #endif
  #endif


protected:
  virtual void DoDispose (void);

private:

  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTransmit (Time dt);
  void Send (void);
  void Reset (Ptr<Socket> socket);

  uint32_t m_count;
  uint64_t m_allowed;
  Time m_interval;
  uint32_t m_size;

  uint32_t m_sent;
  Ptr<Socket> m_socket;
  Address m_peerAddress;
  uint16_t m_peerPort;
  EventId m_sendEvent;

  uint16_t m_pg;

};

} // namespace ns3

#endif /* UDP_CLIENT_H */
