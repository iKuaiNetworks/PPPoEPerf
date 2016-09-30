#ifndef PPP_RANDOM_H_
#define PPP_RANDOM_H_

#include <climits>
#include <boost/random.hpp>
#include <boost/generator_iterator.hpp>
#include <boost/random/random_device.hpp>

class PPPRandom {
public:
	PPPRandom() : gen(rd()), dis(INT_MIN, INT_MAX)
	{}

	int generate_random_int(void)
	{  return dis(gen);  }

private:
	boost::random::random_device rd;
	boost::random::mt19937 gen;
	boost::random::uniform_int_distribution<> dis;
};

#endif
