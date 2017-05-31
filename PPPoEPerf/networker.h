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

#ifndef PPPOE_PROF_NET_WORKER_H
#define PPPOE_PROF_NET_WORKER_H
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/bind.hpp>

#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <unistd.h>

#include <functional>
#include <memory>
#include <thread>
#include <string>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <memory>

#include "pppoe_worker.h"
#include "logger.hpp"
#include "test_config.h"
#include "test_stats.h"

namespace asio = boost::asio;
using boost::asio::deadline_timer;

struct NetUnit : public std::enable_shared_from_this<NetUnit> {
 public:
  struct pkt_ppoe_t {
    eth_frame ef;
    pppoe_pkt ps;
    ppp_header ph;
  };

  struct pkt_t {
    pkt_t() { memset(buf, 0, IP_MAXPACKET); }

    unsigned char buf[IP_MAXPACKET];
    size_t len;
    struct sockaddr_ll dst;
  };

 public:
  NetUnit(unsigned int id, unsigned int ip, const char* srv,
          const std::string& str);

 public:
  std::shared_ptr<NetUnit::pkt_t> send_internal();

 private:
  int compose_pppoe(unsigned char* p, unsigned int len);
  void get_mac_info();

 private:
  unsigned int sid_;
  unsigned int id_;
  std::string ip_;
  unsigned char srv_mac_[6];
  unsigned char local_mac_[6];
  int if_idx_;
  std::string ifname_;
};

// frame send utility
struct TaskSend {
 public:
  TaskSend(int fd, unsigned id, const MacAddr& srv)
      : sock_(fd), shutdown_(false) {
    dst_addr_.sll_ifindex = id;
    dst_addr_.sll_halen = ETH_ALEN;
    dst_addr_.sll_family = AF_PACKET;
    memcpy(dst_addr_.sll_addr, srv, 6);
  }

 public:
  void send_proc() {
    printf("TaskSend send frame tid: %ld and pid: %ld\n",
           (long)syscall(__NR_gettid), (long)getpid());
    int ec_snd;
    do {
      ec_snd = sendto(sock_, NULL, 0,
                      0,  // use block send
                      (struct sockaddr*)&dst_addr_, sizeof(struct sockaddr_ll));

      if (ec_snd < 0) {
        PPP_LOG(error) << "TaskSend sendto failed, erro: " << strerror(errno);
        usleep(10);
      } else if (ec_snd == 0) {
        usleep(10);
      } else {
        PPP_LOG(trace) << "TaskSend send sucess";
      }
    } while (!shutdown_);

    PPP_LOG(trace) << "TaskSend send end";
  }

  void stop() { shutdown_ = true; }

 private:
  int sock_;
  bool shutdown_;
  struct sockaddr_ll dst_addr_;
};

class NetWorker : public std::enable_shared_from_this<NetWorker> {
 public:
  NetWorker(const std::string& ifname, asio::io_service& ios)
      : ifname_(ifname),
        first_node_(true),
        ios_(ios),
        timer_(ios),
        cur_use_block_(0) {
    fd_sock_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    memset(srv_addr_, 0, sizeof(srv_addr_));
  }

  void add_unit(unsigned int sid, unsigned int ip, const MacAddr& srv) {
    ios_.post(std::bind(&NetWorker::claim_unit, shared_from_this(), sid, ip,
                        (const char*)srv));
    PPP_LOG(trace) << "NetWorker add_unit";
    if (first_node_) {  // only once
      PPP_LOG(trace) << "create thread now";
      first_node_ = false;
      memcpy(srv_addr_, srv, 6);
      sendor_ = std::make_shared<TaskSend>(fd_sock_, if_idx_, srv);
      auto th = std::make_shared<std::thread>(
          std::bind(&TaskSend::send_proc, sendor_));

      thread_group_.push_back(th);
    }
  }

  void claim_unit(unsigned int sid, unsigned int ip, const char* srv) {
    std::shared_ptr<NetUnit> nu =
        std::make_shared<NetUnit>(sid, ip, srv, ifname_);
    PPP_LOG(trace) << "NetWorker claim_unit sid:" << sid;
    units_[sid] = nu;
  }

  void remove_unit(unsigned int sid) {
    ios_.post(std::bind(&NetWorker::release_unit, shared_from_this(), sid));
  }

  void release_unit(unsigned int sid) {
    auto it = units_.find(sid);
    if (it == units_.end()) {
      PPP_LOG(error) << "NetWorker not found sid: " << sid;
      return;
    }
    units_.erase(it);
  }

  void start() {
    PPP_LOG(trace) << "NetWorker start";
    if (!initial()) {
      PPP_LOG(error) << "NetWorker initial failed";
      return;
    }
    if (if_idx_ == -1) {
      PPP_LOG(error) << "NetWorker get_if_idx failed";
      return;
    }

    auto th = std::make_shared<std::thread>(
        std::bind(&NetWorker::loop, shared_from_this()));

    thread_group_.push_back(th);
  }

  void stop() {
    if (sendor_) {
      sendor_->stop();
    }
    ios_.stop();
  }

  void join() {
    for (size_t i = 0; i < thread_group_.size(); ++i) {
      thread_group_[i]->join();
    }
  }

 private:
  bool initial();

  int get_if_idx() {
    struct ifreq req;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
      return -1;
    }
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname_.c_str(), sizeof(req.ifr_name) - 1);

    if (-1 == ioctl(s, SIOCGIFINDEX, &req)) {
      close(s);
      return -1;
    }
    close(s);

    return req.ifr_ifindex;
  }

  void loop() {
    printf("network fill frame tid: %ld and pid: %ld\n",
           (long)syscall(__NR_gettid), (long)getpid());
    timer_.expires_from_now(boost::posix_time::seconds(1));
    timer_.async_wait(boost::bind(&NetWorker::task_fill, shared_from_this()));

    ios_.run();
    PPP_LOG(trace) << "NetWorker loop leave";
  }

  void task_fill() {
    struct tpacket_hdr* hdr;
    std::shared_ptr<NetUnit::pkt_t> pppoe_pkt;
    size_t loop = 1;
    auto iter = units_.begin();
    size_t data_offset = TPACKET_HDRLEN - sizeof(struct sockaddr_ll);
    char* data;

    for (; iter != units_.end(); ++iter) {
      for (size_t i = 0; i < 50; ++i) {
        do {
          hdr = (struct tpacket_hdr*)(((char*)pkt_hdr_start_) +
                                      (packet_req_.tp_block_size *
                                       cur_use_block_));
          data = (char*)((char*)hdr + data_offset);

          switch ((volatile uint32_t)(hdr->tp_status)) {
            case TP_STATUS_AVAILABLE:
              // fill packet
              if (pkt_map_.find(iter->first) == pkt_map_.end()) {
                pkt_map_[iter->first] = iter->second->send_internal();
              }
              pppoe_pkt = pkt_map_[iter->first];
              memcpy(data, pppoe_pkt->buf, pppoe_pkt->len);
              PPP_LOG(trace) << "NetWorker task_fill sid:" << iter->first;
              loop = 0;
              break;
            case TP_STATUS_WRONG_FORMAT:
              PPP_LOG(error) << "NetWorker task_fill block wrong format";
              exit(EXIT_FAILURE);
            default:
              PPP_LOG(trace) << "NetWorker task_fill return hdr->status:"
                             << (uint32_t)(hdr->tp_status);
              usleep(0);
              break;
          }
        } while (loop == 1);

        cur_use_block_++;
        loop = 1;
        if (cur_use_block_ == packet_req_.tp_block_nr) {
          cur_use_block_ = 0;
        }
        hdr->tp_len = pppoe_pkt->len;
        hdr->tp_status = TP_STATUS_SEND_REQUEST;
      }
    }
    PPP_LOG(trace) << "NetWorker fill packet";
    fill_dealer();
  }

  void fill_dealer() {
    PPP_LOG(trace) << "NetWorker fill dealer";
    TestStats* stats = Singleton<TestStats>::instance_ptr();
    TestConfig* config = Singleton<TestConfig>::instance_ptr();

    if (!config->max_padi_cnt_ ||
        stats->padi_send_ok_ < config->max_padi_cnt_) {
      timer_.expires_from_now(boost::posix_time::seconds(1));
      timer_.async_wait(boost::bind(&NetWorker::task_fill, shared_from_this()));
    } else {
      //		timer_.expires_from_now(boost::posix_time::milliseconds(2));
      timer_.expires_from_now(boost::posix_time::seconds(2));
      timer_.async_wait(boost::bind(&NetWorker::task_fill, shared_from_this()));
    }
  }

 private:
  NetWorker(const NetWorker&);
  void operator=(const NetWorker&);

 private:
  int fd_sock_;
  std::string ifname_;
  int if_idx_;
  MacAddr srv_addr_;

  bool first_node_;
  std::vector<std::shared_ptr<std::thread> > thread_group_;
  std::map<unsigned int, std::shared_ptr<NetUnit> > units_;
  asio::io_service& ios_;
  asio::deadline_timer timer_;
  std::shared_ptr<TaskSend> sendor_;

  struct tpacket_req packet_req_;
  struct tpacket_hdr* pkt_hdr_start_;
  unsigned int cur_use_block_;
  std::map<unsigned int, std::shared_ptr<NetUnit::pkt_t> > pkt_map_;
};

#endif
