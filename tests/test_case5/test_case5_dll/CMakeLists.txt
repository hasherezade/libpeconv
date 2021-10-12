cmake_minimum_required ( VERSION 2.8...3.21 )
project (test_case5_dll)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
include_directories ( include )

set (srcs
	main.cpp
)

set (dll_hdrs
	include/api.h
)

add_library ( ${PROJECT_NAME} SHARED ${dll_hdrs} ${srcs} main.def)

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
