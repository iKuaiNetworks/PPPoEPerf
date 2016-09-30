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
