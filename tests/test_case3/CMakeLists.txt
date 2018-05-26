cmake_minimum_required (VERSION 2.8)
project (test_case3)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	main.cpp
	checksum.cpp
)

set (hdrs
	checksum.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs})
