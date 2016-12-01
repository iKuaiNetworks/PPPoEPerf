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
