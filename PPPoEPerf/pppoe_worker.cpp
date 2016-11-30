// ikuai is pleased to support the open source community by making PPPoEPerf available.
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


#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <algorithm>
#include <iterator>
#include <functional>

#include <openssl/md5.h>
#include <boost/foreach.hpp>

#include "singleton.h"
#include "test_config.h"
#include "test_stats.h"
#include "pppoe_worker.h"
#include "ppp_random.h"
#include "logger.hpp"

PPPoEWorker::PPPoEWorker(pt::ptree root)
{
  BOOST_FOREACH(pt::ptree::value_type& elem, root.get_child("account"))
  {
    std::string usr = elem.first;
    std::string passwd = elem.second.data();
    secrets_[usr] = passwd;
  }
  assert(!secrets_.empty());
  iter_last = secrets_.begin();
  login_period_ = root.get<uint32_t>("period");
  login_rate_   = root.get<uint16_t>("login-rate");
}

bool PPPoEWorker::init(void)
{
	PPP_LOG(trace) << "PPPoEWorker init";
	if (!get_src_if_info()) {
		PPP_LOG(error) << "PPPoEWorker failed to get src mac "
			       << Singleton<TestConfig>::instance_ptr()->interface_;
		return false;
	}

	random_ptr_ = std::make_shared<PPPRandom>();
	sock_ptr_ = std::make_shared<RawSocket>();
	return sock_ptr_->init();
}

bool PPPoEWorker::bind_interface(const std::string &ifname)
{
	PPP_LOG(trace) << "PPPoEWorker bind interface";
	return sock_ptr_->bind_interface(ifname);
}

void PPPoEWorker::start(void)
{
	PPP_LOG(trace) << "PPPoEWorker start";
	thread_ = std::make_shared<std::thread>(std::bind(&PPPoEWorker::loop, this));
}

void PPPoEWorker::loop()
{
	TestConfig *config = Singleton<TestConfig>::instance_ptr();
	TestStats *stats = Singleton<TestStats>::instance_ptr();
	time_t start, cur, last_send;
	struct timeval timeout;

	start = cur = time(NULL);
	fd_set rdset;
	int ret;

	memset(stats, 0, sizeof(TestStats));
	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;
	last_send = 0;

	do {
		if (cur > last_send) //time unit is second
		{
			last_send = time(NULL);
			if ((!config->max_padi_cnt_)
			        || (stats->padi_send_ok_ < config->max_padi_cnt_))
			{
				uint32_t distance = config->max_padi_cnt_ - stats->padi_send_ok_;
				if (distance >= login_rate_) {
					distance = login_rate_;
				}
				for (size_t i = 0; i < distance; ++i)
				{
					if (send_padi()) {
						++stats->padi_send_ok_;
						PPP_LOG(info) << "PPPoEWorker send padi "
							      << stats->padi_send_ok_
							      << " times";
					} else {
						PPP_LOG(error) << "PPPoEWorker send padi failed "
							       << "with error info "
							       << strerror(errno);
						++stats->padi_send_fail_;
					}
				}
			}
		}

		offline();
		relogin();

		FD_ZERO(&rdset);
		FD_SET(sock_ptr_->get_sock_fd(), &rdset);
		ret = select(sock_ptr_->get_sock_fd()+1, &rdset, NULL, NULL, &timeout);
		if (0 == ret) {
			// timeout 
			cur = time(NULL);
			process_expired_events(cur);
			timeout.tv_sec = 0;
			timeout.tv_usec = 1000;

			if (ppp_timeout_event_.size()) {
				auto it = ppp_timeout_event_.begin();
				if (it->timeout_secs_ <= cur) {
					PPP_LOG(error) << "PPPoEWorker expired event not processed";
				} else {
					unsigned int left = it->timeout_secs_ - cur;
					if (left*1000 < 1*1000) {
						PPP_LOG(info) << "PPPoEWorker set select timeout with "
							       << left << " s";
						timeout.tv_sec = left*1000;
						timeout.tv_usec = 0;
					}
				}
			}
		} else if (-1 == ret) {
			break;
		} else {
			if (FD_ISSET(sock_ptr_->get_sock_fd(), &rdset)) {
				recv_pkt();
			}
			cur = time(NULL);
			timeout.tv_sec = 0;
			timeout.tv_usec = 1000;
		}
	}
	while (start + config->duration_ >= cur);
	//to inform other thread to finish the thread
	struct tpacket_stats packet_stats;
	memset(&packet_stats, 0, sizeof(packet_stats));
	socklen_t len = 4;
	getsockopt(sock_ptr_->get_sock_fd(), SOL_PACKET, PACKET_STATISTICS, &packet_stats, &len);
	PPP_LOG(info) << "tp packets : %d" << packet_stats.tp_packets;
	PPP_LOG(info) << "tp drops : %d" << packet_stats.tp_drops;
	do_stop();
}

void PPPoEWorker::stop(void)
{}

void PPPoEWorker::join()
{  thread_->join();  }

bool PPPoEWorker::get_src_if_info()
{
	TestConfig *config = Singleton<TestConfig>::instance_ptr();
	struct ifreq req;

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		return false;
	}
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, config->interface_.c_str(), sizeof(req.ifr_name)-1);
	if (-1 == ioctl(s, SIOCGIFHWADDR, &req)) {
		close(s);
		return false;
	}
	memcpy(&src_if_mac_, req.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	if (-1 == ioctl(s, SIOCGIFINDEX, &req)) {
		close(s);
		return false;
	}
	src_if_index_ = req.ifr_ifindex;
	close(s);
	
	return true;
}

void PPPoEWorker::get_local_mac(MacAddr addr)
{
	memcpy(addr, src_if_mac_, 6);
}

bool PPPoEWorker::send_padi(void)
{
	struct {
		struct eth_frame ef;
		struct pppoe_pkt  di;
		struct pppoe_tag tag;
	} pkt;
 	struct sockaddr_ll dst;

 	dst.sll_ifindex = src_if_index_;
 	dst.sll_halen = ETH_ALEN;

 	memset(dst.sll_addr, 0xff, sizeof(src_if_mac_));
	memset(pkt.ef.dst_, 0xff, sizeof(pkt.ef.dst_));	
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));

	pkt.ef.type_ = htons(ETH_P_PPP_DISC);
	pkt.di.ver_ = PPPOE_DISC_VER;
	pkt.di.type_ = PPPOE_DISC_TYPE;
	pkt.di.code_  = PPPOE_DISC_CODE_PADI;
	pkt.di.session_id_ = 0;
	pkt.di.length_ = htons(4);
	pkt.tag.type_ = htons(PPPOE_TAG_SERVICE_NAME);
	pkt.tag.len_ = 0;

	return sock_ptr_->send_frame(&pkt, sizeof(pkt), (struct sockaddr *)&dst, sizeof(dst));
}

bool PPPoEWorker::send_padr(struct PPPoEServer &server)
{
	union {
		struct {
			struct eth_frame ef;
			struct pppoe_pkt  dr;
		};
		unsigned char tag_data[1500];
	} pkt;
 	struct sockaddr_ll dst;
 	unsigned int tag_size = 0;
 	unsigned char *tag_data;

 	dst.sll_ifindex = src_if_index_;
 	dst.sll_halen = ETH_ALEN;
 	memcpy(dst.sll_addr, server.svc_mac_, sizeof(server.svc_mac_));

	// Fill ethernet
	memcpy(pkt.ef.dst_, server.svc_mac_, sizeof(pkt.ef.dst_));
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));
	pkt.ef.type_ = htons(ETH_P_PPP_DISC);

	//Calculate the TAG service name len
	tag_size = 4+server.svc_name_.size();
	//Calculate the TAG ac cookie len
	if (server.ac_cookie_.size()) {
		tag_size += 4+server.ac_cookie_.size();
	}

	// Fill PPPoE
	pkt.dr.ver_ = PPPOE_DISC_VER;
	pkt.dr.type_ = PPPOE_DISC_TYPE;
	pkt.dr.code_  = PPPOE_DISC_CODE_PADR;
	pkt.dr.session_id_ = 0;
	pkt.dr.length_ = htons(tag_size);

	// Fill PPPoE Tag
	tag_data = reinterpret_cast<unsigned char *>(&pkt.dr+1);
	// Fill service name
	*reinterpret_cast<unsigned short *>(tag_data) = htons(PPPOE_TAG_SERVICE_NAME);
	tag_data += 2;
	*reinterpret_cast<unsigned short *>(tag_data) = htons(server.svc_name_.size());
	tag_data += 2;
	memcpy(tag_data, &server.svc_name_[0], server.svc_name_.size());
	tag_data += server.svc_name_.size();

	if (server.ac_cookie_.size()) {
		*reinterpret_cast<unsigned short *>(tag_data) = htons(PPPOE_TAG_AC_COOKIE);
		tag_data += 2;
		*reinterpret_cast<unsigned short *>(tag_data) = htons(server.ac_cookie_.size());
		tag_data += 2;
		memcpy(tag_data, &server.ac_cookie_[0], server.ac_cookie_.size());
		tag_data += server.ac_cookie_.size();
	}

	return sock_ptr_->send_frame(&pkt, tag_data-pkt.tag_data, (struct sockaddr *)&dst, sizeof(dst));	
}

bool PPPoEWorker::send_padt(MacAddr mac, unsigned short session_id)
{
	union {
		struct {
			struct eth_frame ef;
			struct pppoe_pkt  dr;
		};
	} pkt;
 	struct sockaddr_ll dst;

 	dst.sll_ifindex = src_if_index_;
 	dst.sll_halen = ETH_ALEN;
	memcpy(dst.sll_addr, mac, 6);

	// Fill ethernet
	memcpy(pkt.ef.dst_, mac, sizeof(pkt.ef.dst_));

	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));
	pkt.ef.type_ = htons(ETH_P_PPP_DISC);

	// Fill PPPoE
	pkt.dr.ver_ = PPPOE_DISC_VER;
	pkt.dr.type_ = PPPOE_DISC_TYPE;
	pkt.dr.code_  = PPPOE_DISC_CODE_PADT;
	pkt.dr.session_id_ = htons(session_id);
	pkt.dr.length_ = 0;

	cache_.erase(session_id);

	return sock_ptr_->send_frame(&pkt, sizeof(pkt), (struct sockaddr *)&dst, sizeof(dst));	
}

bool PPPoEWorker::send_lcp_config_req(const MacAddr server_mac, unsigned short session_id)
{
	union {
		struct {
			struct eth_frame  ef;
			struct pppoe_pkt  ps;
			struct ppp_header ph;
			struct lcp_pkt    lp;
			unsigned char     opt_data[1480];
		};
	} pkt;
 	struct sockaddr_ll dst;
 	PPPEntry pe(session_id, server_mac);
 	unsigned short data_size = 0;
 	unsigned char *opt;

 	dst.sll_ifindex = src_if_index_;
 	dst.sll_halen = ETH_ALEN;
 	memcpy(dst.sll_addr, server_mac, sizeof(MacAddr));

	// Fill ethernet
	memcpy(pkt.ef.dst_, server_mac, sizeof(pkt.ef.dst_));
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));
	pkt.ef.type_ = htons(ETH_P_PPP_SES);

	//Cacluate lenfth of LCP options
	//MRU
	data_size += 4;
	//Magic Number
	data_size += 6;

	// Fill PPPoE
	pkt.ps.ver_ = PPPOE_DISC_VER;
	pkt.ps.type_ = PPPOE_DISC_TYPE;
	pkt.ps.code_  = PPPOE_SESS_CODE_DATA;
	pkt.ps.session_id_ = htons(session_id);
	pkt.ps.length_ = htons(data_size+sizeof(pkt.ph)+sizeof(pkt.lp));//the rest payload size

	// Fill PPP
	pkt.ph.proto_ = htons(PPP_PROTO_LCP);

	// Fill LCP
	pkt.lp.code_ = LCP_CODE_CONFIG_REQ;
	pkt.lp.id_ = pe.ppp_id_;
	pe.ppp_id_++;
	pkt.lp.len_ = htons(data_size+sizeof(pkt.lp));

	// Fill LCP options
	opt = pkt.opt_data;
	// MRU
	*opt = LCP_CONFIG_OPT_MRU;
	++opt;
	*opt = 4;
	++opt;
	*reinterpret_cast<unsigned short *>(opt) = htons(sizeof(pkt.opt_data));
	opt += 2;
	// Magic Number
	*opt = LCP_CONFIG_OPT_MAGIC_NUM;
	++opt;
	*opt = 6;
	++opt;
	*reinterpret_cast<unsigned int *>(opt) = htons(random_ptr_->generate_random_int());
	opt += 4;

	pe.status_ = PPP_STATUS_CONFIG_REQUEST;

	ppp_entry_.insert(pe);
	return sock_ptr_->send_frame(&pkt,
					opt-reinterpret_cast<unsigned char *>(&pkt),
					(struct sockaddr *)&dst,
					sizeof(dst));
}

bool PPPoEWorker::send_lcp_config_ack(const MacAddr server_mac,
					unsigned short session_id,
					unsigned char id,
					LCPOptList &opt_list)
{
	union {
		struct {
			struct eth_frame  ef;
			struct pppoe_pkt  ps;
			struct ppp_header ph;
			struct lcp_pkt    lp;
			unsigned char     opt_data[1480];
		};
	} pkt;
 	struct sockaddr_ll dst;
 	unsigned short data_size = 0;
 	unsigned char *opt;

 	dst.sll_ifindex = src_if_index_;
 	dst.sll_halen = ETH_ALEN;
 	memcpy(dst.sll_addr, server_mac, sizeof(MacAddr));

	// Fill ethernet
	memcpy(pkt.ef.dst_, server_mac, sizeof(pkt.ef.dst_));
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));
	pkt.ef.type_ = htons(ETH_P_PPP_SES);

	//Cacluate lenfth of LCP options
	for (auto it = opt_list.begin(); it != opt_list.end(); ++it) {
		data_size += (*it)->len_;
	}

	// Fill PPPoE
	pkt.ps.ver_ = PPPOE_DISC_VER;
	pkt.ps.type_ = PPPOE_DISC_TYPE;
	pkt.ps.code_  = PPPOE_SESS_CODE_DATA;
	pkt.ps.session_id_ = htons(session_id);
	pkt.ps.length_ = htons(data_size+sizeof(pkt.ph)+sizeof(pkt.lp));

	// Fill PPP
	pkt.ph.proto_ = htons(PPP_PROTO_LCP);

	// Fill LCP
	pkt.lp.code_ = LCP_CODE_CONFIG_ACK;
	pkt.lp.id_ = id;
	pkt.lp.len_ = htons(data_size+sizeof(pkt.lp));

	// Fill LCP options
	opt = pkt.opt_data;
	for (auto it = opt_list.begin(); it != opt_list.end(); ++it) {
		*opt = (*it)->type_;
		*(opt+1) = (*it)->len_;
		if ((*it)->len_-2) {
			memcpy(opt+2, &(*it)->data_[0], (*it)->len_-2);
		}
		opt += (*it)->len_;
	}
	
	return sock_ptr_->send_frame(&pkt,
					opt-reinterpret_cast<unsigned char *>(&pkt),
					(struct sockaddr *)&dst,
					sizeof(dst));
}

bool PPPoEWorker::send_lcp_echo_reply(const MacAddr server_mac, unsigned short session_id, unsigned char id)
{
	union {
		struct {
			struct eth_frame ef;
			struct pppoe_pkt  ps;
			struct ppp_header ph;
			struct lcp_pkt    lp;
			unsigned char     opt_data[4];
		};
	} pkt;
 	struct sockaddr_ll dst;
 	unsigned short data_size = 0;

 	dst.sll_ifindex = src_if_index_;
 	dst.sll_halen = ETH_ALEN;
 	memcpy(dst.sll_addr, server_mac, sizeof(MacAddr));

	// Fill ethernet
	memcpy(pkt.ef.dst_, server_mac, sizeof(pkt.ef.dst_));
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));
	pkt.ef.type_ = htons(ETH_P_PPP_SES);

	//Cacluate lenfth of LCP options
	data_size = 4;// magic number's size

	// Fill PPPoE
	pkt.ps.ver_ = PPPOE_DISC_VER;
	pkt.ps.type_ = PPPOE_DISC_TYPE;
	pkt.ps.code_  = PPPOE_SESS_CODE_DATA;
	pkt.ps.session_id_ = htons(session_id);
	pkt.ps.length_ = htons(data_size+sizeof(pkt.ph)+sizeof(pkt.lp));

	// Fill PPP
	pkt.ph.proto_ = htons(PPP_PROTO_LCP);

	// Fill LCP
	pkt.lp.code_ = LCP_CODE_ECHO_REP;
	pkt.lp.id_ = id;
	pkt.lp.len_ = htons(data_size+sizeof(pkt.lp));

	// Fill LCP options
	int rand_num = random_ptr_->generate_random_int();
	rand_num = htons(rand_num);
	memcpy(pkt.opt_data, &rand_num, sizeof(int));

	return sock_ptr_->send_frame(&pkt, sizeof(pkt), (struct sockaddr *)&dst, sizeof(dst));
}

bool PPPoEWorker::send_chap_reply(const MacAddr server_mac,
					unsigned short session_id,
					unsigned short id,
					unsigned char* chal,
					size_t chal_size)
{
	union {
		struct {
			struct eth_frame ef;
			struct pppoe_pkt ps;
			struct ppp_header ph;
			struct lcp_pkt chap;
			unsigned char data[1480];
		};
	}pkt;

	struct sockaddr_ll dst;
	std::string name_ = name();
	unsigned short data_size = 1 + MD5_DIGEST_LENGTH + name_.size(); //name fgao_test
	unsigned char digest[MD5_DIGEST_LENGTH] = {0};
	unsigned char idbyte = id;
	std::string secret_ = secret(name_);

	cache_[session_id] = name_; //update cache info

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, &idbyte, 1);
	MD5_Update(&ctx, (unsigned char*)secret_.c_str(), secret_.size());
	MD5_Update(&ctx, chal, chal_size);
	MD5_Final(digest, &ctx);

	dst.sll_ifindex = src_if_index_;
	dst.sll_halen = ETH_ALEN;
	memcpy(dst.sll_addr, server_mac, sizeof(MacAddr));

	memcpy(pkt.ef.dst_, server_mac, sizeof(pkt.ef.dst_));
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));

	pkt.ef.type_ = htons(ETH_P_PPP_SES);

	pkt.ps.ver_ = PPPOE_DISC_VER;
	pkt.ps.type_ = PPPOE_DISC_TYPE;
	pkt.ps.code_ = PPPOE_SESS_CODE_DATA;
	pkt.ps.session_id_ = htons(session_id);
	pkt.ps.length_ = htons(sizeof(pkt.ph) + sizeof(pkt.chap) + data_size);

	pkt.ph.proto_ = htons(PPP_PROTO_CHAN_HANDSHAKE_AUTH);

	pkt.chap.code_ = CHAP_RESPONSE;
	pkt.chap.id_ = id;
	pkt.chap.len_ = htons(sizeof(pkt.chap) + data_size);

	char s = MD5_DIGEST_LENGTH;
	memcpy(pkt.data, &s, 1);
	memcpy(pkt.data+1, digest, MD5_DIGEST_LENGTH);
	memcpy(pkt.data+1+MD5_DIGEST_LENGTH, name_.data(), name_.size());

	return sock_ptr_->send_frame(&pkt,
					pkt.data+1+MD5_DIGEST_LENGTH
						+name_.size()
						-reinterpret_cast<unsigned char*>(&pkt),
					(struct sockaddr*)&dst,
					sizeof(dst));
}

void PPPoEWorker::insert_expired_event(unsigned short sid, unsigned int timeout)
{
	unsigned int expired_time = time(NULL)+timeout;
	PPPTimeoutEvent timeout_event(sid, expired_time);
	PPPSesEvent ses_event(sid, expired_time);

	ppp_timeout_event_.insert(timeout_event);
	ppp_ses_event_.insert(ses_event);
}

void PPPoEWorker::reset_expired_event(unsigned short sid, unsigned int timeout)
{
	unsigned int expired_time = time(NULL)+timeout;
	PPPTimeoutEvent timeout_event(sid, expired_time);
	PPPSesEvent ses_event(sid, expired_time);

	auto it = ppp_ses_event_.find(ses_event);
	if (it != ppp_ses_event_.end()) {
		it->timeout_secs_ = expired_time;		
	} else {
		PPP_LOG(error) << "PPPoEWorker not find session event " << sid;
		ppp_ses_event_.insert(ses_event);		
	}

	ppp_timeout_event_.insert(timeout_event);
}


void PPPoEWorker::remove_expired_event(unsigned short sid)
{
	PPPSesEvent tmp_se(sid, 0);
	auto sit = ppp_ses_event_.find(tmp_se);
	
	if (sit != ppp_ses_event_.end()) {
		bool find = false;
		PPPTimeoutEvent tmp_te(0, sit->timeout_secs_);
		auto eit = ppp_timeout_event_.find(tmp_te);
		
		if (eit != ppp_timeout_event_.end()) {
			for (; eit != ppp_timeout_event_.end(); ++eit) {
				if (eit->session_id_ == sit->session_id_) {
					find = true;
					break;
				}
				if (eit->timeout_secs_ > sit->timeout_secs_) {
					break;
				}
			}
		} else {
			PPP_LOG(error) << "PPPoEWorker not find expired event " << sit->timeout_secs_;
		}

		if (find) {
			ppp_timeout_event_.erase(eit);
		}

		ppp_ses_event_.erase(sit);
	}
}

void PPPoEWorker::process_expired_events(time_t cur_time)
{
	TestStats *stats = Singleton<TestStats>::instance_ptr();
	TestConfig *test_config = Singleton<TestConfig>::instance_ptr();
	std::multiset<PPPTimeoutEvent>::const_iterator eit = ppp_timeout_event_.begin();

	for (; eit != ppp_timeout_event_.end();)
	{
		PPPEntry pe(eit->session_id_);
		if (eit->timeout_secs_ > cur_time) {
			break;
		}
		pe.session_id_ = eit->session_id_;
		PPP_LOG(trace) << "PPPoEWorker deal timout list with session " << pe.session_id_;
		ppp_timeout_event_.erase(eit++);
		auto pit = ppp_entry_.find(pe);
		if (pit != ppp_entry_.end()) {
			switch (pit->status_) {
				case PPP_STATUS_CONFIG_REQUEST:
				{
					PPP_LOG(info) << "PPPoEWorker resend LCP config request session id " << pit->session_id_;
					stats->lcp_config_req_resend_++;
					if (send_lcp_config_req(pit->server_mac_, pit->session_id_)) {
						stats->lcp_config_req_send_ok_++;
					} else {
						stats->lcp_config_req_send_fail_++;
					}
					reset_expired_event(pit->session_id_, test_config->resend_timeout_);
					break;
				}
				default: break;
			}
		}
	}
}

#define MAX_FRAME_SIZE		(1500)
void PPPoEWorker::recv_pkt(void)
{
	struct {
		union {
			unsigned char data[MAX_FRAME_SIZE];
			struct eth_frame frame;
		};
	} buffer;
	ssize_t ret;

	ret = recv(sock_ptr_->get_sock_fd(), &buffer, sizeof(buffer), MSG_DONTWAIT);
	if (-1 == ret) {
		PPP_LOG(error) << "PPPoEWorker failed to receive with error info " << strerror(errno);
		return;
	}
	if (static_cast<unsigned int>(ret) <= sizeof(struct eth_frame)) {
		PPP_LOG(error) << "PPPoEWorker packet size error";
		return;
	}

	switch (ntohs(buffer.frame.type_)) {
		case ETH_P_PPP_DISC:
			process_pppoe_disc_pkt(buffer.data, static_cast<unsigned int>(ret));
			break;
		case ETH_P_PPP_SES:
			process_pppoe_session_pkt(buffer.data, static_cast<unsigned int>(ret));
			break;
		default:
			break;
	}
}

bool PPPoEWorker::parsed_pppoe_tag_data(unsigned char *data, unsigned data_size, PPPoEServer &server)
{
	TestStats *test_stats = Singleton<TestStats>::instance_ptr();
	const unsigned char *tag_data = data;
	std::string tmp_data;
	unsigned int parsed_size = 0;
	unsigned short type;
	unsigned short len;

	do {
		type = *(reinterpret_cast<const unsigned short *>(tag_data+parsed_size));
		type = ntohs(type);
		parsed_size += 2;
		len = *(reinterpret_cast<const unsigned short *>(tag_data+parsed_size));
		len = ntohs(len);
		parsed_size += 2;
	
		if (parsed_size+len > data_size) {
			PPP_LOG(error) << "PPPoEWorker invalid tag size: " << parsed_size;
			return false;
		}
	
		switch (type) {
			case PPPOE_TAG_SERVICE_NAME:
				for (int i = 0; i < len; ++i) {
					server.svc_name_.push_back(*(tag_data+parsed_size+i));
				}
				break;
			case PPPOE_TAG_AC_NAME:
				for (int i = 0; i < len; ++i) {
					server.ac_name_.push_back(*(tag_data+parsed_size+i));
				}
				break;
			case PPPOE_TAG_AC_COOKIE:
				for (int i = 0; i < len; ++i) {
					server.ac_cookie_.push_back(*(tag_data+parsed_size+i));
				}
				break;
			case PPPOE_TAG_END_OF_LIST:
				//Reach end
				return true;
			case PPPOE_TAG_GENERIC_ERR:
				tmp_data.clear();
				for (int i = 0; i < len; ++i) {
					tmp_data.push_back(*(tag_data+parsed_size+i));
				}
				PPP_LOG(info) << "PPPoEWorker generic error";
				test_stats->generic_err_++;
				server.err_signal_ = true;
				break;
			case PPPOE_TAG_AC_SYSTEM_ERR:
				tmp_data.clear();
				for (int i = 0; i < len; ++i) {
					tmp_data.push_back(*(tag_data+parsed_size+i));
				}
				PPP_LOG(info) << "PPPoEWorker ac system error";
				test_stats->ac_system_err_++;
				server.err_signal_ = true;
				break;
			case PPPOE_TAG_SVC_NAME_ERR:
				tmp_data.clear();
				for (int i = 0; i < len; ++i) {
					tmp_data.push_back(*(tag_data+parsed_size+i));
				}
				PPP_LOG(info) << "PPPoEWorker server name error";
				server.err_signal_ = true;
				test_stats->svc_name_err_++;
				break;
			default:
				break;
		}
		parsed_size += len;
	} while (parsed_size < data_size);

	return true;
}

bool PPPoEWorker::process_pppoe_disc_pkt(unsigned char * data, unsigned int size)
{
	struct eth_frame *frame = reinterpret_cast<struct eth_frame *>(data);
	struct pppoe_pkt *pkt = reinterpret_cast<struct pppoe_pkt *>(frame+1);
	TestConfig *test_config = Singleton<TestConfig>::instance_ptr();
	unsigned int tag_size = size-sizeof(*frame)-sizeof(*pkt);
	TestStats *stats = Singleton<TestStats>::instance_ptr();
	PPPoEServer server;

	if (size <= sizeof(*pkt)) {
		PPP_LOG(error) << "PPPoEWorker invalid pppoe response, size:" << size;
		stats->invalid_disc_pkt_++;
		return false;
	}

	if (pkt->ver_ != PPPOE_DISC_VER) {
		PPP_LOG(error) << "PPPoEWorker invalid version :" << static_cast<uint8_t>(pkt->ver_);
		stats->invalid_disc_pkt_++;
		return false;
	}
	if (pkt->type_ != PPPOE_DISC_TYPE) {
		PPP_LOG(error) << "PPPoEWorker invalid type:" << static_cast<uint8_t>(pkt->type_);
		stats->invalid_disc_pkt_++;
		return false;
	}

	memcpy(server.svc_mac_, frame->src_, sizeof(frame->src_));
	switch (pkt->code_) {
		case PPPOE_DISC_CODE_PADO:
			PPP_LOG(info) << "PPPoEWorker receive one pado response";
			stats->pado_rcv_++;
			if (pkt->session_id_ != 0) {
				PPP_LOG(error) << "PPPoEWorker receive one error pado";
				stats->invalid_pado_++;
				return false;
			}
			pkt->length_ = ntohs(pkt->length_);
			if (pkt->length_ > tag_size) {
				PPP_LOG(error) << "PPPoEWorker pado package invalid length";
				stats->invalid_pado_++;
				return false;
			}

			if (tag_size < 4) {
				PPP_LOG(error) << "PPPoEWorker pado package invalid tag size";
				stats->invalid_pado_++;
				return false;
			}

			if (!parsed_pppoe_tag_data(pkt->data_, tag_size, server)) {
				PPP_LOG(error) << "PPPoEWorker pado package invalid tag";
				stats->invalid_pado_++;
				return false;
			}

			if (server.err_signal_) {
				PPP_LOG(error) << "PPPoEWorker pado package deny signal";
				stats->denied_pado_++;
				return true;
			}

			if (!server.svc_name_.size()) {
				PPP_LOG(error) << "PPPoEWorker pado package with no service name";
				stats->invalid_pado_++;
				return false;
			}
			if (!server.ac_name_.size()) {
				PPP_LOG(error) << "PPPoEWorker pado package with no ac name";
				stats->invalid_pado_++;
				return false;
			}

			stats->valid_pado_++;

			if (!test_config->just_discover_) {
				// response, send padr
				if (send_padr(server)) {
					stats->padr_send_ok_++;
				} else {
					stats->padr_send_fail_++;
					PPP_LOG(error) << "PPPoEWorker send padr failed with error info "
						       << strerror(errno);
				}
			}

			if (servers_.find(server) != servers_.end()) {
				return true;
			}
			servers_.insert(server);
			stats->pppoe_server_++;

			std::cout << server << std::endl;
			break;
		case PPPOE_DISC_CODE_PADS:
			PPP_LOG(trace) << "PPPoEWorker receive one pads response";
			stats->pads_rcv_++;
			if (servers_.find(server) == servers_.end()) {
				PPP_LOG(error) << "PPPoEWorker receive a pads responses should not receive";
				return false;
			}

			pkt->session_id_ = ntohs(pkt->session_id_);
			pkt->length_ = ntohs(pkt->length_);
			PPP_LOG(info) << "PPPoEWorker receive session id " << static_cast<uint16_t>(pkt->session_id_);
			if (pkt->length_ > tag_size) {
				PPP_LOG(error) << "PPPoEWorker receive invalid length " << static_cast<uint16_t>(pkt->length_);
				stats->invalid_pads_++;
				return false;
			}

			if (!parsed_pppoe_tag_data(pkt->data_, tag_size, server)) {
				PPP_LOG(error) << "PPPoEWorker receive invalid tag data";
				stats->invalid_pads_++;
				return false;
			}

			if (server.err_signal_) {
				PPP_LOG(error) << "PPPoEWorker receive deny pads";
				stats->denied_pads_++;
				return false;
			}

			if (!server.svc_name_.size()) {
				PPP_LOG(error) << "PPPoEWorker receive pads with no service name";
				stats->invalid_pads_++;
				return false;
			}
			stats->valid_pads_++;
			valid_sid_.insert(pkt->session_id_);
			if (test_config->terminate_) {
				if (send_padt(server.svc_mac_, pkt->session_id_)) {
					PPP_LOG(info) << "PPPoEWorker send padt with sid " << static_cast<uint16_t>(pkt->session_id_);
					stats->padt_send_ok_++;
				} else {
					stats->padt_send_fail_++;
				}
			}
			break;
		case PPPOE_DISC_CODE_PADT:
			stats->padt_rcv_++;
			if (pkt->session_id_ == 0) {
				PPP_LOG(error) << "PPPoEWorker receive padt with invalid session id "
                                               << "session id: " << static_cast<uint16_t>(pkt->session_id_);
				stats->invalid_padt_++;
				return false;
			}
			pkt->session_id_ = ntohs(pkt->session_id_);
			if (servers_.find(server) == servers_.end()) {
				PPP_LOG(error) << "PPPoEWorker receive padt with invalid server";
				return false;
			}

			if (valid_sid_.find(pkt->session_id_) == valid_sid_.end()) {
				PPP_LOG(error) << "PPPoEWorker receive padt session id not found "
		                               << "session id: " << static_cast<uint16_t>(pkt->session_id_);
				stats->invalid_padt_++;
				return false;
			}

			pkt->length_ = ntohs(pkt->length_);
			if (pkt->length_ > tag_size) {
				PPP_LOG(error) << "PPPoEWorker receive padt with invalid tag"
					       << "session id: " << static_cast<uint16_t>(pkt->session_id_);
				stats->invalid_padt_++;
				return false;
			}
			PPP_LOG(info) << "PPPoEWorker receive padt response "
				      << "session id: " << static_cast<uint16_t>(pkt->session_id_);
			stats->valid_padt_++;
			valid_sid_.erase(pkt->session_id_);
			if (active_padt_.find(pkt->session_id_) != active_padt_.end()) {
				active_padt_.erase(pkt->session_id_);
			} else {
				PPP_LOG(error) << "PPPoEWorker receive unexpected padt";
				stats->unexpect_padt_++;
			}
			do_cancel(pkt->session_id_);
			break;
		case PPPOE_DISC_CODE_PADI:
		case PPPOE_DISC_CODE_PADR:
			break;
		default:
			break;
	}

	return true;
}

bool PPPoEWorker::parsed_lcp_opt_data(unsigned char *data, unsigned int data_size, LCPOptList &opt_list)
{
	unsigned int parsed_size = 0;
	int i;
	
	do {
		ParsedLCPOptPtr opt = std::make_shared<ParsedLCPOpt>();
		opt->type_ = *(data+parsed_size);
		opt->len_ = *(data+1+parsed_size);
		if (opt->len_+parsed_size > data_size) {
			PPP_LOG(error) << "PPPoEWorker parsed lcp opt data failed";
			return false;
		}
		for (i = 0; i < opt->len_-2; ++i) {
			opt->data_.push_back(*(data+2+parsed_size+i));
		}
		parsed_size += opt->len_;
		opt_list.push_back(opt);
	} while (parsed_size < data_size);

	return true;
}

void PPPoEWorker::set_ppp_auth_method(unsigned short sid, LCPOptList &opt_list)
{
	PPPEntry pe(sid);
	auto it = ppp_entry_.find(pe);

	if (it != ppp_entry_.end()) {
		for (auto oit = opt_list.begin(); oit != opt_list.end(); ++oit) {
			if ((*oit)->type_ == LCP_CONFIG_OPT_AUTH_PROTO) {
				const unsigned char *data = &(*oit)->data_[0];
				unsigned short proto = *reinterpret_cast<const unsigned short *>(data);
				data += 2;
				proto = ntohs(proto);
				if (PPPEntry::PPP_AUTH_PROTO_CHAP != proto) {
					PPP_LOG(error) << "PPPoEWorker unsupport auth proto";
					break;
				}
				if (PPPEntry::PPP_AUTH_ALGO_MD5 != *data) {
					PPP_LOG(error) << "PPPoEWorker unsupport algorithm";
					break;
				}
				it->auth_proto_ = proto;
				it->auth_algo_ = *data;
			}
		}
	} else {
		PPP_LOG(error) << "PPPoEWorker cannot find entry by id " << sid;
	}
}

void PPPoEWorker::set_ppp_entry_status(unsigned short sid, int new_status)
{	
	PPPEntry pe(sid);
	auto it = ppp_entry_.find(pe);
	if (it != ppp_entry_.end()) {
		it->status_ = new_status;
	}
}

bool PPPoEWorker::get_chap_challenge(const unsigned char* data,
					unsigned int sz,
					unsigned char** chal,
					unsigned int* chal_size)
{
	unsigned char value_size = *data;
	if (value_size > sz) {
		PPP_LOG(error) << "PPPoEWorker invalid valid size";
		return false;
	}
	*chal = (unsigned char*)malloc(value_size);
	memcpy(*chal, data+1, value_size);
	*chal_size =  value_size;

	std::string name((const char*)(data+1+value_size), sz - 1 - value_size);
	return true;
}

bool PPPoEWorker::set_ipcp(unsigned short sid, LCPOptList& opt_list)
{
	PPPEntry pe(sid);
	auto it = ppp_entry_.find(pe);
	if (it == ppp_entry_.end()) return false;
	LCPOptList::iterator item = opt_list.begin();

	for (; item != opt_list.end(); item++)
	{
		unsigned char* data = &((*item)->data_[0]);
		if ((*item)->type_ == IPCP_IP_ADDR) {
			memcpy((void*)it->ipaddr_, data, 4);
		} else if ((*item)->type_ == IPCP_DNS_PRI) {
			memcpy((void*)it->pri_dns_, data, 4);
		} else if ((*item)->type_ == IPCP_DNS_SEC) {
			memcpy((void*)it->sec_dns_, data, 4);
		} else {
			PPP_LOG(error) << "PPPoEWorker receive other ipcp data type";
		}
	}
	return true;
}

bool PPPoEWorker::send_ipcp_ack(const MacAddr server_mac, unsigned short session_id, unsigned char id)
{
	return send_ipcp(server_mac, session_id, id, false);
}

bool PPPoEWorker::send_ipcp_req(const MacAddr server_mac, unsigned short session_id, unsigned char id)
{
	return send_ipcp(server_mac, session_id, id, true);
}

bool PPPoEWorker::send_ipcp(const MacAddr server_mac,
				unsigned short session_id,
				unsigned char id, bool req)
{
	union {
		struct {
			struct eth_frame ef;
			struct pppoe_pkt ps;
			struct ppp_header ph;
			struct lcp_pkt ipcp;
			unsigned char data[1480];
		};
	}pkt;

	PPPEntry pe(session_id);
	auto it = ppp_entry_.find(pe);
	if (it == ppp_entry_.end()) 
		return false;

	size_t data_size = 6;//at least 6
	if (!req && strlen((const char*)it->pri_dns_) == 0) {
		//nothing
	} else {
		data_size += 6;//pri dns
		data_size += 6;//sec dns
	}

	struct sockaddr_ll dst;
	dst.sll_ifindex = src_if_index_;
	dst.sll_halen = ETH_ALEN;
	memcpy(dst.sll_addr, server_mac, sizeof(MacAddr));
	memcpy(pkt.ef.dst_, server_mac, sizeof(pkt.ef.dst_));
	MacAddr addr; get_local_mac(addr);
	memcpy(pkt.ef.src_, addr, sizeof(src_if_mac_));

	pkt.ef.type_ = htons(ETH_P_PPP_SES);

	pkt.ps.ver_ = PPPOE_DISC_VER;
	pkt.ps.type_ = PPPOE_DISC_TYPE;
	pkt.ps.code_ = PPPOE_SESS_CODE_DATA;
	pkt.ps.session_id_ = htons(session_id);
	pkt.ps.length_ = htons(sizeof(pkt.ph) + sizeof(pkt.ipcp) + data_size);

	pkt.ph.proto_ = htons(PPP_PROTO_IPCP);

	if (req) {
		pkt.ipcp.code_ = CONFIG_REQUEST;
		id += 1;
	} else {
		pkt.ipcp.code_ = CONFIG_ACK;
	}

	pkt.ipcp.id_ = id;
	pkt.ipcp.len_ = htons(sizeof(pkt.ipcp) + data_size);

	//whatever you should fill the ipaddr, even it is 0.0.0.0
	unsigned char* ptr = pkt.data;
	unsigned int payload = 0;
	unsigned c = 6;
	*ptr = IPCP_IP_ADDR; ptr += 1;
	memcpy(ptr, &c ,1); ptr += 1;
	memcpy(ptr, it->ipaddr_, 4); ptr += 4;
	payload = 6;

	if (!req && strlen((const char*)it->pri_dns_) == 0) {
		payload = 6;
	} else {
		*ptr = IPCP_DNS_PRI; ptr += 1;
		memcpy(ptr, &c ,1); ptr += 1;
		memcpy(ptr, it->pri_dns_, 4); ptr += 4;
		payload += 6;

		*ptr = IPCP_DNS_SEC; ptr += 1;
		memcpy(ptr, &c ,1); ptr += 1;
		memcpy(ptr, it->sec_dns_, 4);
		payload += 6;
	}

	return sock_ptr_->send_frame(&pkt, pkt.data+payload - reinterpret_cast<unsigned char*>(&pkt),
					(struct sockaddr*)&dst, sizeof(dst));
}

std::string PPPoEWorker::name()
{
	//before all the client login, the rlogin_names_ should be empty
	if (!rlogin_names_.empty()) {
		return rlogin_names_.at(0);
	} else {
		return iter_last->first;
	}
}

std::string PPPoEWorker::secret(const std::string& usr)
{
	std::string passwd = secrets_[usr];

	if (!rlogin_names_.empty()) {
		rlogin_names_.erase(rlogin_names_.begin()); //delete it
		PPP_LOG(info) << "PPPoEWorker secret erase one offline";
	} else {
		++iter_last;
		if (iter_last == secrets_.end()) {
			iter_last = secrets_.begin();
		}
	}

	return passwd;
}

void PPPoEWorker::deal_ipcp_ack(unsigned int sid)
{
	PPPEntry pe(sid);
	auto it = ppp_entry_.find(pe);
	if (it == ppp_entry_.end()){
		PPP_LOG(error) << "PPPoEWorker deal ipcp ack failed with sid " << sid;
		return;
	}

	auto iter = cache_.find(sid);
	if (iter == cache_.end()) {
		PPP_LOG(error) << "PPPoEWorker deal ipcp ack cache find sid failed" << sid;
		return;
	}
	time_t now = time(NULL);
	onlines_.insert(std::make_pair((uint64_t)now, sid));//update the onlines info
	unsigned int ip;
	memcpy(&ip, it->ipaddr_, 4);
	do_add(sid, ip, it->server_mac_);
}

void PPPoEWorker::offline() //online -> offline
{
	time_t now = time(NULL);
	auto iter = onlines_.begin();

	for (; iter != onlines_.end();)
	{
		if (now - iter->first < login_period_) {
			break;
		}
		offlines_.insert(std::make_pair((uint64_t)now, cache_[iter->second]));
		PPP_LOG(info) << "PPPoEWorker offline usr: " << cache_[iter->second];
		do_offline(iter->second);
		onlines_.erase(iter++);
	}
}

void PPPoEWorker::do_offline(unsigned int uid)
{
	PPPEntry pe(uid);

	auto iter = ppp_entry_.find(pe);
	if (iter == ppp_entry_.end()) {
		PPP_LOG(error) << "PPPoEWorker do_offline failed to find uid";
		return;
	}

	if (!send_padt((unsigned char*)iter->server_mac_, uid)) {
		PPP_LOG(error) << "PPPoEWorker do_offline send padt failed";
		return;
	}

	TestStats *stats = Singleton<TestStats>::instance_ptr();
	stats->padt_send_ok_++;
	active_padt_.insert(uid);
}

void PPPoEWorker::relogin()
{
	time_t cur = time(NULL);
	auto iter = offlines_.begin();

	for (; iter != offlines_.end();)
	{
		if (cur - iter->first < login_period_) {
			break;
		}
		PPP_LOG(info) << "PPPoEWorker relogin usr: " << iter->second;
		do_relogin();
		offlines_.erase(iter++);
	}
}

void PPPoEWorker::do_relogin()
{
	send_padi();
}

bool PPPoEWorker::is_valid_session(unsigned short sid)
{
	PPPEntry pe(sid);

	return (ppp_entry_.find(pe) != ppp_entry_.end());
}

bool PPPoEWorker::is_valid_session(unsigned short sid, int match_status)
{
	PPPEntry pe(sid);
	auto pit = ppp_entry_.find(pe);

	return (pit != ppp_entry_.end() &&  pit->status_ == match_status);
}

bool PPPoEWorker::process_pppoe_session_pkt(unsigned char * data, unsigned int size)
{
	struct eth_frame *frame = reinterpret_cast<struct eth_frame *>(data);
	struct pppoe_pkt *pkt = reinterpret_cast<struct pppoe_pkt *>(frame+1);
	struct ppp_header *ph = reinterpret_cast<struct ppp_header*>(pkt+1);
	TestStats *stats = Singleton<TestStats>::instance_ptr();
	TestConfig *test_config = Singleton<TestConfig>::instance_ptr();
	struct lcp_pkt *lp;
	unsigned char *opt_data;
	LCPOptList opt_list;
	unsigned int data_size;
	unsigned char* chal_num = NULL;
	unsigned int chal_size;

	if (size <= sizeof(*pkt)) {
		PPP_LOG(error) << "PPPoEWorker receive invalid pkt";
		stats->invalid_sess_pkt_++;
		return false;
	}

	if (pkt->ver_ != PPPOE_DISC_VER) {
		PPP_LOG(error) << "PPPoEWorker receive invalid version";
		stats->invalid_sess_pkt_++;
		return false;
	}
	if (pkt->type_ != PPPOE_DISC_TYPE) {
		PPP_LOG(error) << "PPPoEWorker receive invalid type";
		stats->invalid_sess_pkt_++;
		return false;
	}
	if (pkt->code_ != PPPOE_SESS_CODE_DATA) {
		PPP_LOG(error) << "PPPoEWorker receive invalid code";
		stats->invalid_sess_pkt_++;
		return false;
	}
	pkt->session_id_ = ntohs(pkt->session_id_);
	if (valid_sid_.find(pkt->session_id_) == valid_sid_.end()) {
		stats->invalid_sess_pkt_++;
		return false;
	}

	ph->proto_ = ntohs(ph->proto_);
	switch (ph->proto_) {
	case PPP_PROTO_LCP:
		lp = reinterpret_cast<struct lcp_pkt*>(ph+1);
		lp->len_ = ntohs(lp->len_);
		data_size = size - sizeof(*frame) - sizeof(*pkt) - sizeof(*ph) - sizeof(*lp);
		switch (lp->code_) {
			case LCP_CODE_CONFIG_REQ:
				PPP_LOG(info) << "PPPoEWorker receive LCP config request sid "
					      << static_cast<uint16_t>(pkt->session_id_);
				stats->lcp_config_req_rcv_++;
				if (lp->len_ > data_size) {
					PPP_LOG(error) << "PPPoEWorker receive lcp invalid data size";
					stats->invalid_lcp_config_req_++;
					return false;
				}
				opt_data = reinterpret_cast<unsigned char *>(lp+1);
				if (!parsed_lcp_opt_data(opt_data, lp->len_-sizeof(*lp), opt_list)) {
					PPP_LOG(error) << "PPPoEWorker parse lcp opt failed";
					stats->invalid_lcp_config_req_++;
					return false;
				}
				stats->valid_lcp_config_req_++;
				if (send_lcp_config_ack(frame->src_, pkt->session_id_, lp->id_, opt_list)) {
					stats->lcp_config_ack_send_ok_++;
					PPP_LOG(info) << "PPPoEWorker send lcp config ack with sid "
						      << static_cast<uint16_t>(pkt->session_id_);
				} else {
					stats->lcp_config_ack_send_fail_++;
				}

				if (send_lcp_config_req(frame->src_, pkt->session_id_)) {
					stats->lcp_config_req_send_ok_++;
					PPP_LOG(info) << "PPPoEWorker send lcp config req with sid "
						      << static_cast<uint16_t>(pkt->session_id_);
				} else {
					stats->lcp_config_req_send_fail_++;
				}
				set_ppp_auth_method(pkt->session_id_, opt_list);
				PPP_LOG(trace) << "PPPoEWorker insert timeout to list with sid "
					       << static_cast<uint16_t>(pkt->session_id_);
				insert_expired_event(pkt->session_id_, test_config->resend_timeout_);
				break;
			case LCP_CODE_CONFIG_ACK:
				stats->lcp_config_ack_rcv_++;
				if (!is_valid_session(pkt->session_id_, PPP_STATUS_CONFIG_REQUEST)) {
					PPP_LOG(error) << "PPPoEWorker receive lcp config ack with invalid sid "
						       << static_cast<uint16_t>(pkt->session_id_);
					stats->invalid_lcp_config_ack_++;
					remove_expired_event(pkt->session_id_);
					return false;
				}
				PPP_LOG(info) << "PPPoEWorker receive lcp config ack with sid "
					      << static_cast<uint16_t>(pkt->session_id_);
				stats->valid_lcp_config_ack_++;
				remove_expired_event(pkt->session_id_);
				set_ppp_entry_status(pkt->session_id_, PPP_STATUS_CONFIG_ACK);
				break;
			case LCP_CODE_ECHO_REQ:
				stats->lcp_echo_reqeust_rcv_++;
				if (!is_valid_session(pkt->session_id_)) {
					PPP_LOG(error) << "PPPoEWorker receive lcp echo with invalid sid "
						       << static_cast<uint16_t>(pkt->session_id_);
					stats->invalid_lcp_echo_request_++;
					return false;
				}
				stats->valid_lcp_echo_request_++;
				PPP_LOG(info) << "PPPoEWorker receive lcp echo with sid " << static_cast<uint16_t>(pkt->session_id_);

				opt_data = reinterpret_cast<unsigned char *>(lp+1);
				if (send_lcp_echo_reply(frame->src_, pkt->session_id_, lp->id_)) {
					PPP_LOG(info) << "PPPoEWorker send lcp echo reply with sid " << static_cast<uint16_t>(pkt->session_id_);
					stats->lcp_echo_reply_send_ok_++;
				} else {
					stats->lcp_echo_reply_send_fail_++;
					PPP_LOG(error) << "PPPoEWorker send lcp echo failed" << static_cast<uint16_t>(pkt->session_id_);
				}
				break;
			case LCP_CODE_CONFIG_REJ:
				PPP_LOG(error) << "PPPoEWorker " << static_cast<uint16_t>(pkt->session_id_) << " receive lcp config rej";
				break;
			case LCP_CODE_TERM_REQ:
				PPP_LOG(error) << "PPPoEWorker " << static_cast<uint16_t>(pkt->session_id_) << " receive lcp term reqest";
				do_cancel(pkt->session_id_);
				break;
			case LCP_CODE_TERM_ACK:
				PPP_LOG(error) << "PPPoEWorker " << static_cast<uint16_t>(pkt->session_id_) << " receive lcp term ack";
				do_cancel(pkt->session_id_);
				break;
			case LCP_CODE_PROTO_REJ:
				PPP_LOG(error) << "PPPoEWorker " << static_cast<uint16_t>(pkt->session_id_) << " receive lcp proto rej";
				break;
			case LCP_CODE_DISA_REQ:
				PPP_LOG(error) << "PPPoEWorker " << static_cast<uint16_t>(pkt->session_id_) << " receive lcp disa req";
				break;
			default:
				break;
		}
		break;
	case PPP_PROTO_CHAN_HANDSHAKE_AUTH:
		lp = reinterpret_cast<struct lcp_pkt*>(ph+1);
		lp->len_ = ntohs(lp->len_);
		data_size = size - sizeof(*frame) - sizeof(*pkt) - sizeof(*ph) - sizeof(*lp);
		switch (lp->code_) {
		case CHAP_CHALLENGE:
			stats->ppp_chap_challenge_rcv_++;
			if (lp->len_ > data_size) {
				PPP_LOG(error) << "PPPoEWorker receive invalid chap handshake";
				stats->invalid_ppp_chap_challenge_++;
				return false;
			}
			PPP_LOG(info) << "PPPoEWorker receive chap handshake req with sid " << static_cast<uint16_t>(pkt->session_id_);
			opt_data = reinterpret_cast<unsigned char*>(lp+1);
			if (get_chap_challenge(opt_data,
				lp->len_ - sizeof(*lp),
				&chal_num,
				&chal_size)) {
				stats->valid_ppp_chap_challenge_++;
				if (send_chap_reply(frame->src_,
						pkt->session_id_,
						lp->id_,
						chal_num,
						chal_size)) {
					stats->chap_response_send_ok_++;
				} else {
					stats->chap_response_send_fail_++;
					PPP_LOG(error) << "PPPoEWorker send chap handshake resp with sid " << static_cast<uint16_t>(pkt->session_id_);
				}
				delete chal_num;
			} else {
				stats->invalid_ppp_chap_challenge_++;
			}
			break;
		case CHAP_SUCESS:
			PPP_LOG(info) << "PPPoEWorker receive chap sucess with sid " << static_cast<uint16_t>(pkt->session_id_);
			stats->ppp_chap_success_++;
			break;
		case CHAP_FAILURE:
			PPP_LOG(error) << "PPPoEWorker receive chap failed with sid " << static_cast<uint16_t>(pkt->session_id_);
			cache_.erase(pkt->session_id_); //update the cache info
			stats->ppp_chap_failed_++;
			break;
		default: break;
		}

		break;
	case PPP_PROTO_IPCP:
		lp =reinterpret_cast<struct lcp_pkt*>(ph+1);
		lp->len_ = ntohs(lp->len_);
		data_size = size - sizeof(*frame) - sizeof(*pkt) - sizeof(*ph) - sizeof(*lp);
		switch (lp->code_) {
		case CONFIG_REQUEST:
			opt_data = reinterpret_cast<unsigned char*>(lp+1);
			if (!parsed_lcp_opt_data(opt_data, lp->len_-sizeof(*lp), opt_list)) {
				PPP_LOG(error) << "PPPoEWorker receive ipcp with invlid opt";
				return false;
			}
			//send 0.0.0.0
			PPP_LOG(info) << "PPPoEWorker receive ipcp with sid " << static_cast<uint16_t>(pkt->session_id_);
			stats->ppp_ipcp_recv_req_++;
			if (!send_ipcp_req(frame->src_, pkt->session_id_, lp->id_)) {
				PPP_LOG(error) << "PPPoEWorker send ipcp req failed";
				return false;
			}
			stats->ppp_ipcp_send_req_++;
			set_ipcp(pkt->session_id_, opt_list);
			//send server's ack
			if (!send_ipcp_ack(frame->src_, pkt->session_id_, lp->id_)) {
				PPP_LOG(error) << "PPPoEWorker send ipcp ack failed";
				return false;
			}
			stats->ppp_ipcp_send_ack_++;
			break;
		case CONFIG_ACK:
			PPP_LOG(info) << "PPPoEWorker receive ipcp ack with sid " << static_cast<uint16_t>(pkt->session_id_);
			stats->ppp_ipcp_recv_ack_++;
			deal_ipcp_ack(pkt->session_id_);
			//todo:parse the ip dns, and enter next step, try to keep some net flow.
			break;
		case CONFIG_NAK:
			opt_data = reinterpret_cast<unsigned char*>(lp+1);
			if (!parsed_lcp_opt_data(opt_data, lp->len_-sizeof(*lp), opt_list)){
				PPP_LOG(error) << "PPPoEWorker parse ipcp opt failed";
				return false;
			}
			set_ipcp(pkt->session_id_, opt_list);
			stats->ppp_ipcp_recv_nak_++;
			PPP_LOG(info) << "PPPoEWorker receive ipcp nak with sid " << static_cast<uint16_t>(pkt->session_id_);
			if (!send_ipcp_req(frame->src_, pkt->session_id_, lp->id_)) {
				PPP_LOG(error) << "PPPoEWorker send ipcp req failed";
				return false;
			}
			stats->ppp_ipcp_send_req_++;
			break;
		case CONFIG_REJECT:
			PPP_LOG(error) << "PPPoEWorker receive ipcp reject with sid " << static_cast<uint16_t>(pkt->session_id_);
			stats->ppp_ipcp_recv_reject_++;
			break;
		case TERMINATE_REQUEST:
			PPP_LOG(error) << "PPPoEWorker receive ipcp terminate req with sid " << static_cast<uint16_t>(pkt->session_id_);
			stats->ppp_ipcp_recv_term_req_++;
			break;
		case TERMINATE_ACK:
			PPP_LOG(error) << "PPPoEWorker receive ipcp terminate ack with sid " << static_cast<uint16_t>(pkt->session_id_);
			break;
		case CODE_REJECT:
			PPP_LOG(error) << "PPPoEWorker receive ipcp code reject with sid " << static_cast<uint16_t>(pkt->session_id_);

			break;
		default: break;
		}
		break;
	default:
		break;
	}
	
	return true;
}
