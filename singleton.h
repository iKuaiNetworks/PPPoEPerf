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

