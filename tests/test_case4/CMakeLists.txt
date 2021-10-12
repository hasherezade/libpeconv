cmake_minimum_required ( VERSION 2.8...3.21 )
project (test_case4)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(DELAYLOAD_FLAG "/DELAYLOAD:\"user32.dll\"" )

set (srcs
	main.cpp
)

set (hdrs
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )
target_link_libraries(${PROJECT_NAME} "delayimp.lib" )
set_property(TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS " ${DELAYLOAD_FLAG}")

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
