// ikuai is pleased to support the open source community by making PPPoEPerf
// available.
// Copyright (C) 2016 ikuai. All rights reserved.

// This file is part of PPPoEPerf.

// PPPoEPerf is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// PPPoEPerf is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with PPPoEPerf.  If not, see <http://www.gnu.org/licenses/>.

// ---
// Author: Xiaopei Feng <xpfeng@ikuai8.com>

#include "networker.h"
#include "singleton.h"
#include "test_config.h"

#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>
#include <sstream>

#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define UDP_HDRLEN 8   // UDP header length, excludes data

#define MAX_UDP_LENGTH 522000
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
static uint16_t checksum(uint16_t *addr, int len) {
  int count = len;
  uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *)addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload,
                       int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
  ptr += sizeof(iphdr.ip_src.s_addr);
  chksumlen += sizeof(iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
  ptr += sizeof(iphdr.ip_dst.s_addr);
  chksumlen += sizeof(iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0;
  ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
  ptr += sizeof(iphdr.ip_p);
  chksumlen += sizeof(iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
  ptr += sizeof(udphdr.len);
  chksumlen += sizeof(udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
  ptr += sizeof(udphdr.source);
  chksumlen += sizeof(udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
  ptr += sizeof(udphdr.dest);
  chksumlen += sizeof(udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
  ptr += sizeof(udphdr.len);
  chksumlen += sizeof(udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0;
  ptr++;
  *ptr = 0;
  ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy(ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i = 0; i < payloadlen % 2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum((uint16_t *)buf, chksumlen);
}

NetUnit::NetUnit(unsigned int id, unsigned int ip, const char *srv,
                 const std::string &str)
    : sid_(id), ifname_(str) {
  struct in_addr addr;
  addr.s_addr = ip;
  ip_ = inet_ntoa(addr);
  id_ = 0;
  memcpy(srv_mac_, srv, 6);
  get_mac_info();
}

void NetUnit::get_mac_info() {
  struct ifreq req;
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (-1 == s) {
    return;
  }
  memset(&req, 0, sizeof(req));
  strncpy(req.ifr_name, ifname_.c_str(), sizeof(req.ifr_name) - 1);
  if (-1 == ioctl(s, SIOCGIFHWADDR, &req)) {
    close(s);
    return;
  }
  memcpy(&local_mac_, req.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
  if (-1 == ioctl(s, SIOCGIFINDEX, &req)) {
    close(s);
    return;
  }
  if_idx_ = req.ifr_ifindex;
  close(s);
}

std::shared_ptr<NetUnit::pkt_t> NetUnit::send_internal() {
  struct ip iphdr;
  struct udphdr udphdr;
  struct sockaddr_ll dst;
  unsigned char ip_flags[4];

  size_t datalen = 1024;
  unsigned char data[1024];
  for (size_t i = 0; i < datalen; ++i) {
    data[i] = 'u';
  }

  memset(&iphdr, 0, sizeof(iphdr));

  iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);
  iphdr.ip_v = 4;
  iphdr.ip_tos = 0;
  iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + datalen);
  iphdr.ip_id = htons(id_);
  ip_flags[0] = ip_flags[1] = ip_flags[2] = ip_flags[3] = 0;

  iphdr.ip_off = htons(0x4000);
  iphdr.ip_ttl = 255;
  iphdr.ip_p = IPPROTO_UDP;

  PPP_LOG(info) << "NetUnit create ip packet src ip: " << ip_;
  if (inet_pton(AF_INET, ip_.c_str(), &(iphdr.ip_src)) != 1) {
    PPP_LOG(error) << "NetUnit inet_pton failed";
    return std::make_shared<NetUnit::pkt_t>();
  }
  if (inet_pton(AF_INET, "192.168.100.1", &(iphdr.ip_dst)) != 1) {
    PPP_LOG(error) << "NetUnit inet_pton failed";
    return std::make_shared<NetUnit::pkt_t>();
  }

  iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);
  // udp
  udphdr.source = htons(4951);
  udphdr.dest = htons(4950);
  udphdr.len = htons(UDP_HDRLEN + datalen);
  udphdr.check = udp4_checksum(iphdr, udphdr, data, datalen);

  unsigned char *pkt_buf = (unsigned char *)malloc(IP_MAXPACKET);
  memset(pkt_buf, 0, IP_MAXPACKET);
  int frame_sz = compose_pppoe(pkt_buf, IP4_HDRLEN + UDP_HDRLEN + datalen);
  memcpy(pkt_buf + frame_sz, &iphdr, IP4_HDRLEN);
  memcpy(pkt_buf + frame_sz + IP4_HDRLEN, &udphdr, UDP_HDRLEN);
  memcpy(pkt_buf + frame_sz + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

  dst.sll_ifindex = if_idx_;
  dst.sll_halen = ETH_ALEN;
  memcpy(dst.sll_addr, srv_mac_, 6);

  std::shared_ptr<NetUnit::pkt_t> package = std::make_shared<NetUnit::pkt_t>();
  memcpy(package->buf, pkt_buf, IP_MAXPACKET);
  package->len = frame_sz + IP4_HDRLEN + UDP_HDRLEN + datalen;
  memcpy(&(package->dst), &dst, sizeof(dst));
  free(pkt_buf);

  return package;
}

int NetUnit::compose_pppoe(unsigned char *p, unsigned int len) {
  pkt_ppoe_t pkt;
  struct sockaddr_ll dst;

  dst.sll_ifindex = if_idx_;
  dst.sll_halen = ETH_ALEN;
  memcpy(dst.sll_addr, srv_mac_, 6);

  memcpy(pkt.ef.dst_, srv_mac_, 6);
  memcpy(pkt.ef.src_, local_mac_, 6);
  pkt.ef.type_ = htons(ETH_P_PPP_SES);

  pkt.ps.ver_ = PPPOE_DISC_VER;
  pkt.ps.type_ = PPPOE_DISC_TYPE;
  pkt.ps.code_ = PPPOE_SESS_CODE_DATA;
  pkt.ps.session_id_ = htons(sid_);
  pkt.ps.length_ = htons(len + 2);
  pkt.ph.proto_ = htons(0x0021);  // ip protocol
  memcpy(p, &pkt, sizeof(pkt));

  return sizeof(pkt_ppoe_t);
}

bool NetWorker::initial() {
  struct sockaddr_ll myaddr;
  struct ifreq s_ifr;

  memset(&myaddr, 0, sizeof(struct sockaddr_ll));
  myaddr.sll_family = PF_PACKET;
  myaddr.sll_protocol = htons(ETH_P_ALL);

  strncpy(s_ifr.ifr_name, ifname_.c_str(), sizeof(s_ifr.ifr_name));
  if (ioctl(fd_sock_, SIOCGIFINDEX, &s_ifr)) {
    PPP_LOG(error) << "NetWorker ioctl failed";
    return false;
  }
  if_idx_ = s_ifr.ifr_ifindex;

  memset(&myaddr, 0, sizeof(struct sockaddr_ll));
  myaddr.sll_family = AF_PACKET;
  myaddr.sll_protocol = ETH_P_ALL;
  myaddr.sll_ifindex = if_idx_;
  if (bind(fd_sock_, (struct sockaddr *)&myaddr, sizeof(myaddr)) == -1) {
    PPP_LOG(error) << "NetWorker bind failed";
  }

  packet_req_.tp_block_size = 1024 * 8;
  packet_req_.tp_frame_size = 1024 * 8;
  packet_req_.tp_block_nr = 1024;
  packet_req_.tp_frame_nr = 1024;

  unsigned long size = packet_req_.tp_block_size * packet_req_.tp_block_nr;
  int mode_loss = 1;
  if (setsockopt(fd_sock_, SOL_PACKET, PACKET_LOSS, (char *)&mode_loss,
                 sizeof(int)) < 0) {
    PPP_LOG(error) << "NetWorker setsocket PACKET_LOSS failed";
    return false;
  }

  if (setsockopt(fd_sock_, SOL_PACKET, PACKET_TX_RING, (void *)&packet_req_,
                 sizeof(packet_req_)) < 0) {
    PPP_LOG(error) << "NetWorker setsockopt packet tx ring failed: "
                   << strerror(errno);
    return false;
  }

  pkt_hdr_start_ = (struct tpacket_hdr *)mmap(0, size, PROT_READ | PROT_WRITE,
                                              MAP_SHARED, fd_sock_, 0);
  if (pkt_hdr_start_ == (void *)-1) {
    PPP_LOG(error) << "NetWorker mmap failed";
    return false;
  }

  return true;
}
