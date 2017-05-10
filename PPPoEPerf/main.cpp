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

#include <iostream>
#include <fstream>
#include <string>
#include <sys/time.h>
#include <sys/resource.h>
#include <functional>

#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/utility/setup.hpp>
#include "logger.hpp"

#include "test_config.h"
#include "test_stats.h"
#include "singleton.h"
#include "pppoe_worker.h"
#include "networker.h"

namespace po = boost::program_options;
namespace logging = boost::log;
using boost::property_tree::json_parser::read_json;
using boost::property_tree::ptree;

void initlog(const std::string &level) {
  logging::register_simple_formatter_factory<logging::trivial::severity_level,
                                             char>("Severity");
  logging::core::get()->add_global_attribute(
      "TimeStamp", logging::attributes::local_clock());
  logging::core::get()->add_global_attribute(
      "ThreadID", logging::attributes::current_thread_id());
  if (level == logging::trivial::to_string(trace)) {
    logging::core::get()->set_filter(severity >= trace);
  } else if (level == logging::trivial::to_string(debug)) {
    logging::core::get()->set_filter(severity >= debug);
  } else if (level == logging::trivial::to_string(info)) {
    logging::core::get()->set_filter(severity >= info);
  } else if (level == logging::trivial::to_string(error)) {
    logging::core::get()->set_filter(severity >= error);
  } else if (level == logging::trivial::to_string(fatal)) {
    logging::core::get()->set_filter(severity >= fatal);
  } else {
    std::cerr << "invalid log level:" << level << std::endl;
    exit(EXIT_FAILURE);
  }

  logging::add_file_log(
      logging::keywords::format =
          "%TimeStamp% [%ThreadID%] <%Severity%>: "
          "%Message%",
      logging::keywords::file_name = "/var/log/pppoe-test-%y%m%dT%H:%M:%S.log",
      logging::keywords::auto_flush = true,
      logging::keywords::rotation_size = 4 * 1024 * 1024,
      logging::keywords::time_based_rotation =
          logging::sinks::file::rotation_at_time_point(0, 0, 0),
      logging::keywords::min_free_space = 20 * 1024 * 1024);
}

int main(int argc, char **argv) {
  po::options_description desc("Allow options");
  desc.add_options()("help,h", "print help messages")
      ("config,c", po::value<std::string>()->default_value("/etc/pppoe_perf/conf.json"), "config file")
      ("resend-timeout", po::value<unsigned int>()->default_value(20),"Specify the resend timeout")
      ("discovery", "Only discover the PPPoE servers")
      ("ppp-stage", "Use ppp-stage")
      ("terminate", "Terminate the session directly")
      ("summary", "Show the summary stats");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
  } catch (const std::exception &e) {
    std::cout << e.what() << std::endl;
    std::cout << desc << "\n";
    return -1;
  }

  if (vm.count("help")) {
    std::cout << desc << std::endl;
    return 0;
  }

  ptree conf;
  {
    std::ifstream ifs(vm["config"].as<std::string>());
    read_json(ifs, conf);
  }

  {
    struct rlimit lim;
    lim.rlim_cur = 10240;
    lim.rlim_max = 10240;
    if (setrlimit(RLIMIT_NOFILE, &lim)) {
      std::cerr << "setrlimit failed" << std::endl;
      return EXIT_FAILURE;
    }
  }

  TestConfig *test_config = Singleton<TestConfig>::instance_ptr();
  test_config->duration_ = conf.get<uint32_t>("duration");
  test_config->interface_ = conf.get<std::string>("interface");
  test_config->max_padi_cnt_ = conf.get<uint32_t>("padi-cnt");
  test_config->period_ = conf.get<uint32_t>("period");
  test_config->resend_timeout_ = 20;

  if (vm.count("discovery")) {
    test_config->just_discover_ = true;
  }
  if (vm.count("ppp-stage")) {
    test_config->ppp_stage_ = true;
  }
  if (vm.count("terminate")) {
    test_config->terminate_ = true;
  }
  if (vm.count("summary")) {
    test_config->show_summary_ = true;
  }

  initlog(conf.get<std::string>("log"));

  if (test_config->max_padi_cnt_) {
    std::cout << "Max count of PADI requests: " << test_config->max_padi_cnt_
              << std::endl;
  }
  if (test_config->just_discover_) {
    std::cout << "Just discover the PPPoE server" << std::endl;
  }
  if (test_config->ppp_stage_) {
    std::cout << "We will enter PPP stage after PPPoE discovery" << std::endl;
  }

  asio::io_service ios;
  std::shared_ptr<PPPoEWorker> worker = std::make_shared<PPPoEWorker>(conf);
  std::shared_ptr<NetWorker> net =
      std::make_shared<NetWorker>(test_config->interface_, ios);
  worker->connect(PPPoEWorker::update_sig(),
                  std::bind(&NetWorker::add_unit, net, std::placeholders::_1,
                            std::placeholders::_2, std::placeholders::_3));

  worker->connect(
      PPPoEWorker::cancel_sig(),
      std::bind(&NetWorker::remove_unit, net, std::placeholders::_1));

  worker->connect(PPPoEWorker::stop_sig(), std::bind(&NetWorker::stop, net));

  if (!worker->init()) {
    std::cout << "Fail to init worker" << std::endl;
    return -1;
  }

  if (!worker->bind_interface(test_config->interface_)) {
    std::cerr << "Fail to bind interface " << test_config->interface_
              << std::endl;
    return -1;
  }

  printf("main tid: %ld and pid: %ld\n", (long)syscall(__NR_gettid),
         (long)getpid());

  worker->start();
  net->start();
  worker->join();
  net->join();

  if (test_config->show_summary_) {
    TestStats *stats = Singleton<TestStats>::instance_ptr();
    std::cout << *stats << std::endl;

    std::fstream fs;
    fs.open("pppoe_perf.txt", std::ios::out | std::ios::trunc);
    fs << stats->get_stats();
    fs.close();
  }

  return 0;
}
