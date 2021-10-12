cmake_minimum_required ( VERSION 2.8...3.21 )
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

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
