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

typedef std::shared_ptr<sinks::synchronous_sink<sinks::text_file_backend>> sink_type;

BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(ppp_logger, logging::sources::severity_logger_mt<severity_level>)

#define PPP_LOG(lvl)        BOOST_LOG_SEV(ppp_logger::get(), lvl)

#endif /* LOGGER_HPP */

