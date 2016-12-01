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

#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/severity_feature.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/smart_ptr.hpp>
#include <memory>

namespace logging = boost::log;
namespace sinks = boost::log::sinks;
using namespace logging::trivial;

typedef std::shared_ptr<sinks::synchronous_sink<sinks::text_file_backend>>
    sink_type;

BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(
    ppp_logger, logging::sources::severity_logger_mt<severity_level>)

#define PPP_LOG(lvl) BOOST_LOG_SEV(ppp_logger::get(), lvl)

#endif /* LOGGER_HPP */
