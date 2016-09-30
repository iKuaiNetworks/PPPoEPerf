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


#ifndef SINGLETON_H_
#define SINGLETON_H_

#include <pthread.h>

#include <memory>
#include <iostream>

template <typename T>
class Singleton {
public:
	Singleton() = delete;
	Singleton(const Singleton &) = delete;
	Singleton & operator= (const Singleton &) = delete;
	
	static T& instance()
	{
		pthread_once(&barrier_, &Singleton::init);
		return *value_;
	}

	static T* instance_ptr()
	{
		pthread_once(&barrier_, &Singleton::init);
		return value_;
	}
	
private:
	static void init()
	{
		value_ = new T();
	}

	static pthread_once_t barrier_;
	static T* value_;
};

template<typename T>
pthread_once_t Singleton<T>::barrier_ = PTHREAD_ONCE_INIT;

template<typename T>
T* Singleton<T>::value_ = NULL;

#endif

