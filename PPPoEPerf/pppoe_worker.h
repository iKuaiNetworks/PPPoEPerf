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

#ifndef PPPOE_WORKER_H_
#define PPPOE_WORKER_H_
#include <boost/signals2.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <string.h>
#include <iomanip>

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <set>
#include <unordered_set>
#include <cstring>
#include <vector>
#include <thread>

namespace pt = boost::property_tree;

class RawSocket;
class PPPRandom;
#define MAC_ADDR_LEN (6)
typedef unsigned char MacAddr[MAC_ADDR_LEN];

struct eth_frame {
  MacAddr dst_;
  MacAddr src_;
  unsigned short type_;
  unsigned char data_[0];
} __attribute__((packed));

enum {
  PPPOE_DISC_VER = 0x01,
  PPPOE_DISC_TYPE = 0x01,
  PPPOE_SESS_CODE_DATA = 0x00,
  PPPOE_DISC_CODE_PADI = 0x09,
  PPPOE_DISC_CODE_PADO = 0x07,
  PPPOE_DISC_CODE_PADR = 0x19,
  PPPOE_DISC_CODE_PADS = 0x65,
  PPPOE_DISC_CODE_PADT = 0xA7,
};

enum {
  PPPOE_TAG_END_OF_LIST = 0x0000,
  PPPOE_TAG_SERVICE_NAME = 0x0101,
  PPPOE_TAG_AC_NAME = 0x0102,
  PPPOE_TAG_AC_COOKIE = 0x0104,
  PPPOE_TAG_SVC_NAME_ERR = 0x0201,
  PPPOE_TAG_AC_SYSTEM_ERR = 0x0202,
  PPPOE_TAG_GENERIC_ERR = 0x0203,
};

enum {
  PPP_PROTO_LCP = 0xC021,
  PPP_PROTO_PWD_AUTH = 0xC023,
  PPP_PROTO_LINK_QUALITY_REPORT = 0xC025,
  PPP_PROTO_CHAN_HANDSHAKE_AUTH = 0xC223,
  PPP_PROTO_IPCP = 0x8021,
};

enum {
  LCP_CODE_CONFIG_REQ = 1,
  LCP_CODE_CONFIG_ACK = 2,
  LCP_CODE_CONFIG_NAK = 3,
  LCP_CODE_CONFIG_REJ = 4,
  LCP_CODE_TERM_REQ = 5,
  LCP_CODE_TERM_ACK = 6,
  LCP_CODE_CODE_REJ = 7,
  LCP_CODE_PROTO_REJ = 8,
  LCP_CODE_ECHO_REQ = 9,
  LCP_CODE_ECHO_REP = 10,
  LCP_CODE_DISA_REQ = 11,
};

enum {
  LCP_CONFIG_OPT_RESERVED = 0,
  LCP_CONFIG_OPT_MRU = 1,
  LCP_CONFIG_OPT_AUTH_PROTO = 3,
  LCP_CONFIG_OPT_QUALITY_PROTO = 4,
  LCP_CONFIG_OPT_MAGIC_NUM = 5,
  LCP_CONFIG_OPT_PROTO_FIELD_COMP = 7,
  LCP_CONFIG_OPT_ADDR_CNTL_FIELD_COMP = 8,
};

enum {
  CHAP_CHALLENGE = 1,
  CHAP_RESPONSE = 2,
  CHAP_SUCESS = 3,
  CHAP_FAILURE = 4,
};

enum {
  PAP_REQUEST = 1,
  PAP_SUCESS = 2,
};

enum {
  CONFIG_REQUEST = 1,
  CONFIG_ACK = 2,
  CONFIG_NAK = 3,
  CONFIG_REJECT = 4,
  TERMINATE_REQUEST = 5,
  TERMINATE_ACK = 6,
  CODE_REJECT = 7,
};

enum {
  IPCP_IP_ADDRES = 1,
  IPCP_IP_COMPRESS = 2,
  IPCP_IP_ADDR = 3,
  IPCP_DNS_PRI = 129,
  IPCP_NBNS_PRI = 130,
  IPCP_DNS_SEC = 131,
  IPCP_NBNS_SEC = 132,
};

struct pppoe_pkt {
  unsigned char ver_ : 4, type_ : 4;
  unsigned char code_;
  unsigned short session_id_;
  unsigned short length_;
  unsigned char data_[0];
} __attribute__((packed));

struct pppoe_tag {
  unsigned short type_;
  unsigned short len_;
  unsigned char data_[0];
} __attribute__((packed));

struct ppp_header {
  unsigned short proto_;
} __attribute__((packed));

struct lcp_pkt {
  unsigned char code_;
  unsigned char id_;
  unsigned short len_;
  unsigned char data_[0];
};

struct lcp_opt {
  unsigned char type_;
  unsigned char len_;
  unsigned char data_[0];
};

struct ParsedLCPOpt {
  unsigned char type_;
  unsigned char len_;
  std::vector<unsigned char> data_;
};

class RawSocket {
 public:
  RawSocket() : raw_sock_(-1) {}

  ~RawSocket() {
    if (-1 != raw_sock_) {
      close(raw_sock_);
    }
  }

  bool init(void) {
    raw_sock_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1 == raw_sock_) {
      std::cerr << "Fail to create raw socket" << std::endl;
      return false;
    }
    int optval = 0;
    socklen_t socklen = 4;

    optval = 512 * 1024;
    socklen = 4;
    setsockopt(raw_sock_, SOL_SOCKET, SO_SNDBUFFORCE, &optval, socklen);

    optval = 5 * 1024 * 1024;
    socklen = 4;
    if (setsockopt(raw_sock_, SOL_SOCKET, SO_RCVBUFFORCE, &optval, socklen)) {
      printf("set SO_RECVBUF failed. error: %s\n", strerror(errno));
    }

    return true;
  }

  void print_buf() {
    int optval = 0;
    socklen_t socklen = 4;
    getsockopt(raw_sock_, SOL_SOCKET, SO_SNDBUF, &optval, &socklen);
    printf("SO_SNDBUF:%d \n", optval);

    optval = 0;
    socklen = 0;
    getsockopt(raw_sock_, SOL_SOCKET, SO_RCVBUF, &optval, &socklen);
    printf("SO_RCVBUF:%d \n", optval);
  }

  bool bind_interface(const std::string &ifname) {
    struct ifreq eth;

    memset(&eth, 0, sizeof(eth));
    strncpy(eth.ifr_ifrn.ifrn_name, ifname.c_str(), IFNAMSIZ);
    if (setsockopt(raw_sock_, SOL_SOCKET, SO_BINDTODEVICE, &eth, sizeof(eth)) ==
        -1) {
      return false;
    }

    return true;
  }

  bool send_frame(const void *buf, unsigned int size, struct sockaddr *dst,
                  unsigned int dst_len) {
    size_t ret = sendto(raw_sock_, buf, size, MSG_DONTROUTE, dst, dst_len);
    if (-1ul == ret) {
      std::cerr << "Fail to send frame: " << strerror(errno) << " errno("
                << errno << ")" << std::endl;
      return false;
    } else if (0 == ret) {
      std::cerr << "Nothing is written" << std::endl;
      return false;
    } else {
      return (ret == size);
    }
  }

  int get_sock_fd(void) { return raw_sock_; }

 private:
  int raw_sock_;
};

namespace signals = boost::signals2;

enum {
  PPP_STATUS_NULL = 0,
  PPP_STATUS_CONFIG_REQUEST = 1,
  PPP_STATUS_CONFIG_ACK = 2,
};

struct PPPEntry {
  enum {
    PPP_AUTH_PROTO_NULL = 0,
    PPP_AUTH_PROTO_CHAP = 0xC223,
    PPP_AUTH_PROTO_PAP = 0xC023,
  };

  enum {
    PPP_AUTH_ALGO_NULL = 0,
    PPP_AUTH_ALGO_MD5 = 0x05,
  };
  PPPEntry(unsigned short sid)
      : session_id_(sid),
        auth_proto_(PPP_AUTH_PROTO_NULL),
        auth_algo_(PPP_AUTH_ALGO_NULL) {
    bzero(ipaddr_, 4);
    bzero(pri_dns_, 4);
    bzero(sec_dns_, 4);
  }
  PPPEntry(unsigned short sid, const MacAddr server_mac)
      : session_id_(sid), ppp_id_(0) {
    memcpy(server_mac_, server_mac, 6);
    bzero(ipaddr_, 4);
    bzero(pri_dns_, 4);
    bzero(sec_dns_, 4);
  }

  bool operator<(const PPPEntry &b) const {
    return b.session_id_ < session_id_;
  }

  unsigned short session_id_;
  unsigned char ppp_id_;
  mutable int status_;
  mutable int auth_proto_;
  mutable int auth_algo_;
  MacAddr server_mac_;
  unsigned char ipaddr_[4];  // allocate ip
  unsigned char pri_dns_[4];  // primary dns
  unsigned char sec_dns_[4];  // secondary dns
};

struct PPPTimeoutEvent {
  PPPTimeoutEvent(unsigned short sid, unsigned int timeout)
      : session_id_(sid), timeout_secs_(timeout) {}

  bool operator<(const PPPTimeoutEvent &b) const {
    return (b.timeout_secs_ < timeout_secs_);
  }
  unsigned short session_id_;
  unsigned int timeout_secs_;
};

struct PPPSesEvent {
  PPPSesEvent(unsigned short sid, unsigned int timeout)
      : session_id_(sid), timeout_secs_(timeout) {}

  bool operator<(const PPPSesEvent &b) const {
    return (b.session_id_ < session_id_);
  }

  unsigned short session_id_;
  mutable unsigned int timeout_secs_;
};

struct ParsedLCPOpt;
typedef std::shared_ptr<ParsedLCPOpt> ParsedLCPOptPtr;
typedef std::vector<ParsedLCPOptPtr> LCPOptList;

struct PPPoEServer {
 public:
  PPPoEServer() : err_signal_(false) {}

  bool operator<(const PPPoEServer &b) const {
    std::string str1((const char *)svc_mac_);
    std::string str2((const char *)b.svc_mac_);

    return str1 < str2;
  }

  friend std::ostream &operator<<(std::ostream &o, PPPoEServer &s) {
    o << "AC Name(" << s.ac_name_ << ") "
      << "Service Name(" << s.svc_name_ << ") "
      << "AC Cookie Len(" << s.ac_cookie_.size() << ") "
      << "MAC(" << std::hex << std::setfill('0') << std::setw(2)
      << static_cast<int>(s.svc_mac_[0]) << ":"
      << static_cast<int>(s.svc_mac_[1]) << ":"
      << static_cast<int>(s.svc_mac_[2]) << ":"
      << static_cast<int>(s.svc_mac_[3]) << ":"
      << static_cast<int>(s.svc_mac_[4]) << ":"
      << static_cast<int>(s.svc_mac_[5]) << ") ";

    return o;
  }

 public:
  std::string svc_name_;
  std::string ac_name_;
  std::vector<unsigned char> ac_cookie_;
  MacAddr svc_mac_;
  bool err_signal_;
};

class PPPoEWorker : public std::enable_shared_from_this<PPPoEWorker> {
 public:
  struct update_sig {};
  struct cancel_sig {};
  struct stop_sig {};

  struct Session {
    Session(const MacAddr mac, unsigned short session, unsigned char cid)
      : sid(session)
      , id (cid)
      , last_echo_stamp(0)
    {
      memcpy(svc_mac, mac, MAC_ADDR_LEN);
    }

    MacAddr svc_mac;
    unsigned short sid;
    unsigned char id;
    uint64_t last_echo_stamp;
  };

 public:
  typedef signals::signal<void(unsigned int sid, unsigned int ip,
                               const MacAddr &mac)> update_signal;
  typedef signals::signal<void(unsigned int sid)> cancel_signal;
  typedef signals::signal<void()> stop_signal;

  PPPoEWorker(pt::ptree root);
  PPPoEWorker(const PPPoEWorker &) = delete;
  PPPoEWorker &operator=(const PPPoEWorker &) = delete;

  bool init();
  bool bind_interface(const std::string &ifname);

  void start();
  void stop();
  void join();

  template <typename S>
  signals::connection connect(update_sig s, const S &slot) {
    return update_.connect(slot);
  }

  template <typename S>
  signals::connection connect(cancel_sig s, const S &slot) {
    return cancel_.connect(slot);
  }

  template <typename S>
  signals::connection connect(stop_sig s, const S &slot) {
    return stop_.connect(slot);
  }

 private:
  bool get_src_if_info(void);
  void get_local_mac(MacAddr addr);

  bool is_valid_session(unsigned short sid);
  bool is_valid_session(unsigned short sid, int match_status);

  bool send_padi(void);
  bool send_padr(struct PPPoEServer &server);
  bool send_padt(MacAddr server, unsigned short session_id);

  bool send_lcp_config_req(const MacAddr server_mac, unsigned short session_id);
  bool send_lcp_config_ack(const MacAddr server_mac, unsigned short session_id,
                           unsigned char id, LCPOptList &opt_list);
  bool send_lcp_echo_reply(const MacAddr server_mac, unsigned short session_id,
                           unsigned char id);

  bool send_lcp_echo_request(const MacAddr server_mac, unsigned short sessid, unsigned char id);

  bool send_chap_reply(const MacAddr server_mac, unsigned short session_id,
                       unsigned short id, unsigned char *chal,
                       size_t chal_size);

  bool send_pap_request(const MacAddr server_mac, unsigned short session_id,
                        unsigned short id);

  void recv_pkt(void);
  void process_expired_events(time_t cur_time);
  void insert_expired_event(unsigned short sid, unsigned int timeout);
  void reset_expired_event(unsigned short sid, unsigned int timeout);
  void remove_expired_event(unsigned short sid);

  bool process_pppoe_disc_pkt(unsigned char *data, unsigned int size);
  bool parsed_pppoe_tag_data(unsigned char *data, unsigned data_size,
                             PPPoEServer &server);
  bool process_pppoe_session_pkt(unsigned char *data, unsigned int size);
  bool parsed_lcp_opt_data(unsigned char *data, unsigned data_size,
                           LCPOptList &opt_list);
  void set_ppp_auth_method(unsigned short sid, LCPOptList &opt_list);
  void set_ppp_entry_status(unsigned short sid, int new_status);
  bool get_chap_challenge(const unsigned char *data, unsigned int sz,
                          unsigned char **chal, unsigned int *chal_size);

  bool set_ipcp(unsigned short sid, LCPOptList &opt_list);
  bool send_ipcp_ack(const MacAddr server_mac, unsigned short session_id,
                     unsigned char id);
  bool send_ipcp_req(const MacAddr server_mac, unsigned short session_id,
                     unsigned char id);
  bool send_ipcp(const MacAddr server_mac, unsigned short session_id,
                 unsigned char id, bool req);
  void loop();

  void do_add(unsigned int sid, unsigned int ip, const MacAddr &mac) {
    update_(sid, ip, mac);
  }

  void do_cancel(unsigned int sid) { cancel_(sid); }

  void do_stop() { stop_(); }

  void check_echo_expired();

  std::string name();
  std::string secret(const std::string &usr);
  int auth_proto(unsigned int sid);
  void deal_ipcp_ack(unsigned int sid);

  void offline();
  void relogin();
  void do_offline(unsigned int uid);
  void do_relogin();

  MacAddr src_if_mac_;
  int src_if_index_;

  typedef std::shared_ptr<RawSocket> RawSocketPtr;
  typedef std::shared_ptr<PPPRandom> PPPRandomPtr;
  RawSocketPtr sock_ptr_;
  PPPRandomPtr random_ptr_;

  std::set<PPPoEServer> servers_;
  std::set<unsigned short> valid_sid_;
  std::set<PPPEntry> ppp_entry_;
  std::multiset<PPPTimeoutEvent> ppp_timeout_event_;
  std::set<PPPSesEvent> ppp_ses_event_;

 private:
  update_signal update_;
  cancel_signal cancel_;
  stop_signal stop_;
  std::shared_ptr<std::thread> thread_;

  typedef std::map<std::string, std::string>::iterator SecretIter;
  SecretIter iter_last;
  std::map<std::string, std::string> secrets_;  // usrname -> passwd
  std::multimap<uint64_t, uint16_t>
      onlines_;  // time->uid  record the online sid
  std::multimap<uint64_t, std::string>
      offlines_;  // time->name record the offline name
  std::vector<std::string> rlogin_names_;
  std::map<uint16_t, std::string>
      cache_;  // sid->name     record the sid mapped name
  uint32_t login_period_;
  uint16_t login_rate_;
  std::unordered_set<uint16_t> active_padt_;
  std::vector<std::shared_ptr<Session> > lcp_echo_list_;
};

typedef std::shared_ptr<PPPoEWorker> PPPoEWorkerPtr;

#endif
