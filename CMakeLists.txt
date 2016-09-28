
# CMake version
cmake_minimum_required (VERSION 2.6)

project(pppoe_perf C CXX)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()
INCLUDE_DIRECTORIES(/usr/include)
set(CMAKE_CXX_FLAGS "-Wall -DBOOST_LOG_DYN_LINK -D_GNU_SOURCE -DSESS_BSIZ -std=c++0x -O2 -ldl -lssl -lpthread")
set(CMAKE_CXX_COMPILER "g++")
set(BOOST_INCLUDEDIR "/opt/boost-1.55.0/include")
set(BOOST_LIBRARYDIR "/opt/boost-1.55.0/lib")
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
#set(Boost_USE_STATIC_LIBS on)
set(OPENSSL_USE_STATIC_LIBS on)

find_package (Threads REQUIRED)
find_package (Boost REQUIRED COMPONENTS program_options regex system log_setup log random)
find_package (OpenSSL REQUIRED COMPONENTS crypo)

if((Boost_FOUND)AND(OPENSSL_FOUND))
	include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
	add_executable(pppoe_perf main.cpp pppoe_worker.cpp networker.cpp)
	INSTALL(TARGETS pppoe_perf
		DESTINATION /usr/bin PERMISSIONS OWNER_READ GROUP_READ WORLD_READ OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE
		COMPONENT libraries
	)
	target_link_libraries(pppoe_perf ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
endif()

set(VERSION "1.0.1")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "pppoe_perf")
set(CPACK_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "xpfeng")
set(CPACK_PACKAGE_VENDOR "ikuai")
#set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/bin")
set(CPACK_PACKAGE_EXECUTABLES "pppoe_perf")
set(CPACK_RPM_PACKAGE_AUTOREQPROV " no")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)
