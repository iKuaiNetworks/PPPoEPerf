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


#ifndef TEST_STATS_H_
#define TEST_STATS_H_
#include <ostream>
#include <sstream>
#include <string>

#include "singleton.h"
#include "test_config.h"

class TestStats {
#define MAX_LEN 3000
public:
	friend std::ostream & operator << (std::ostream &o, TestStats &s)
	{
		TestConfig *test_config = Singleton<TestConfig>::instance_ptr();		
		std::stringstream ss;
		ss << "--------------------------------------------------\n";
		ss << "Send PADI successfully: " << s.padi_send_ok_ << std::endl
		   << "Send PADI failed: " << s.padi_send_fail_ << std::endl
		   << "Send PADR successfully: " << s.padr_send_ok_ << std::endl
		   << "Send PADR failed: " << s.padr_send_fail_ << std::endl
		   << "Send PADT successfully: " << s.padt_send_ok_ << std::endl
		   << "Send PADT failed: " << s.padt_send_fail_ << std::endl
		   << std::endl;
		
		ss << "Recv PADO: " << s.pado_rcv_ << std::endl
		   << "Valid PADO: " << s.valid_pado_ << std::endl
		   << "Denied PADO: " << s.denied_pado_ << std::endl
		   << "Invalid PADO: " << s.invalid_pado_ << std::endl
		   << std::endl;

		ss << "Recv PADS: " << s.pads_rcv_ << std::endl
		   << "Valid PADS: " << s.valid_pads_ << std::endl
		   << "Denied PADS: " << s.denied_pads_ << std::endl
		   << "Invalid PADS: " << s.invalid_pads_ << std::endl
		   << std::endl;

		ss << "Recv PADT: " << s.padt_rcv_ << std::endl
		   << "Valid PADT: " << s.valid_padt_ << std::endl
		   << "Invalid PADT: " << s.invalid_padt_ << std::endl
                   << "Unexpect PADT: " << s.unexpect_padt_ << std::endl
		   << std::endl;

		ss << "Find PPPoE servers: " << s.pppoe_server_ << std::endl
		   << "Invalid disc packet: " << s.invalid_disc_pkt_ << std::endl
		   << "Service-Name-Error: " << s.svc_name_err_ << std::endl
		   << "AC-System-Error: " << s.ac_system_err_ << std::endl
		   << "Generic-Error: " << s.generic_err_ << std::endl;
		ss << "--------------------------------------------------\n";

		if (test_config->ppp_stage_) {
			ss << "Send LCP config request successfully: " << s.lcp_config_req_send_ok_ << std::endl
			   << "Send LCP config request failed: " << s.lcp_config_req_send_fail_ << std::endl
			   << "Resend LCP config request: " << s.lcp_config_req_resend_ << std::endl
			   << "Send LCP config ack successfully: " << s.lcp_config_ack_send_ok_ << std::endl
			   << "Send LCP config ack failed: " << s.lcp_config_ack_send_fail_ << std::endl
			   << "Send LCP echo reply successfully: " << s.lcp_echo_reply_send_ok_ << std::endl
			   << "Send LCP echo reply failed: " << s.lcp_echo_reply_send_fail_ << std::endl
			   << std::endl;

			ss << "Recv LCP config req: " << s.lcp_config_req_rcv_ << std::endl
			   << "Valid LCP config req: " << s.valid_lcp_config_req_ << std::endl
			   << "Invalid LCP config req: " << s.invalid_lcp_config_req_ << std::endl
			   << std::endl;

			ss << "Recv LCP config ack: " << s.lcp_config_ack_rcv_ << std::endl
			   << "Valid LCP config ack: " << s.valid_lcp_config_ack_ << std::endl
			   << "Invalid LCP config ack: " << s.invalid_lcp_config_ack_ << std::endl
			   << std::endl;

			ss << "Recv LCP echo request: " << s.lcp_echo_reqeust_rcv_ << std::endl
			   << "Valid LCP echo request: " << s.valid_lcp_echo_request_ << std::endl
			   << "Invalid LCP echo request: " << s.invalid_lcp_echo_request_ << std::endl
			   << std::endl;

			ss << "Recv PPP CHAP challenge: " << s.ppp_chap_challenge_rcv_++ << std::endl
			   << "Valid PPP CHAP challenge: " << s.valid_ppp_chap_challenge_++ << std::endl
			   << "Invalid PPP CHAP challenge: " << s.invalid_ppp_chap_challenge_++ << std::endl
			   << "PPP CHAP sucess: " << s.ppp_chap_success_ << std::endl
			   << "PPP CHAP failed: " << s.ppp_chap_failed_
			   << std::endl;

			ss << "Recv IPCP request: " << s.ppp_ipcp_recv_req_ << std::endl
			   << "Send IPCP request: " << s.ppp_ipcp_send_req_ << std::endl
			   << "Recv IPCP ack: " << s.ppp_ipcp_recv_ack_ << std::endl
			   << "Send IPCP ack: " << s.ppp_ipcp_send_ack_ << std::endl
			   << "Recv IPCP nak: " << s.ppp_ipcp_recv_nak_ << std::endl
			   << "Recv IPCP reject: " << s.ppp_ipcp_recv_reject_ << std::endl
			   << "Recv IPCP terminal request: " << s.ppp_ipcp_recv_term_req_
			   << std::endl;
		}
		ss << "--------------------------------------------------\n";
		memcpy(s.stats_, ss.str().data(), ss.str().length());
		o << s.stats_;
		return o;
	}

	std::string get_stats()
	{ return stats_;  }

	/******************* PPPoE *********************/	
	unsigned int padi_send_ok_;
	unsigned int padi_send_fail_;
	unsigned int padr_send_ok_;
	unsigned int padr_send_fail_;
	unsigned int padt_send_ok_;
	unsigned int padt_send_fail_;
	
	unsigned int pado_rcv_;
	unsigned int valid_pado_;
	unsigned int denied_pado_;
	unsigned int invalid_pado_;

	unsigned int pads_rcv_;
	unsigned int denied_pads_;
	unsigned int valid_pads_;
	unsigned int invalid_pads_;

	unsigned int padt_rcv_;
	unsigned int valid_padt_;
	unsigned int invalid_padt_;
	unsigned int unexpect_padt_;
	
	unsigned int pppoe_server_;
	unsigned int invalid_disc_pkt_;
	unsigned int svc_name_err_;
	unsigned int ac_system_err_;
	unsigned int generic_err_;

	/******************* PPP *********************/
	unsigned int lcp_config_req_send_ok_;
	unsigned int lcp_config_req_send_fail_;
	unsigned int lcp_config_req_resend_;
	unsigned int lcp_config_ack_send_ok_;
	unsigned int lcp_config_ack_send_fail_;
	unsigned int lcp_echo_reply_send_ok_;
	unsigned int lcp_echo_reply_send_fail_;
	unsigned int chap_response_send_ok_;
	unsigned int chap_response_send_fail_;

	unsigned int lcp_config_req_rcv_;
	unsigned int valid_lcp_config_req_;
	unsigned int invalid_lcp_config_req_;

	unsigned int lcp_config_ack_rcv_;
	unsigned int valid_lcp_config_ack_;
	unsigned int invalid_lcp_config_ack_;

	unsigned int lcp_echo_reqeust_rcv_;
	unsigned int valid_lcp_echo_request_;
	unsigned int invalid_lcp_echo_request_;

	unsigned int ppp_chap_challenge_rcv_;
	unsigned int valid_ppp_chap_challenge_;
	unsigned int invalid_ppp_chap_challenge_;
	unsigned int ppp_chap_success_;
	unsigned int ppp_chap_failed_;
	unsigned int invalid_sess_pkt_;
	unsigned int ppp_ipcp_recv_req_;
	unsigned int ppp_ipcp_send_req_;
	unsigned int ppp_ipcp_recv_ack_;
	unsigned int ppp_ipcp_send_ack_;
	unsigned int ppp_ipcp_recv_nak_;
	unsigned int ppp_ipcp_recv_reject_;
	unsigned int ppp_ipcp_recv_term_req_;

private:
	char stats_[MAX_LEN];
};

#endif
