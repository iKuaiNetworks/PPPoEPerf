#ifndef TEST_CONFIG_H_
#define TEST_CONFIG_H_
#include <string>

class TestConfig {
public:
	std::string server_mac_;
	std::string interface_;
	uint32_t duration_;
	uint32_t request_interval_;
	uint32_t max_padi_cnt_;
	uint32_t resend_timeout_;
	uint32_t period_;

	bool just_discover_;
	bool ppp_stage_;
	bool terminate_;
	bool show_summary_;
	bool show_verbose_;
};

#endif
