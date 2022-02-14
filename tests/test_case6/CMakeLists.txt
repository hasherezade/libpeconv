cmake_minimum_required ( VERSION 3.0 )
project (test_case6)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")

set (srcs
	main.cpp
	sockets.cpp
)

set (hdrs
	callback.h
	main.h
	sockets.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )


#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
