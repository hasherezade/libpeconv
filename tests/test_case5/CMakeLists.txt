cmake_minimum_required ( VERSION 3.0 )
project (test_case5_exe)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	main.cpp
)

set (hdrs
)

# libs
add_subdirectory (test_case5_dll)
include_directories ( test_case5_dll/include )

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )
target_link_libraries(${PROJECT_NAME} "test_case5_dll" )

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
