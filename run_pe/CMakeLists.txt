cmake_minimum_required ( VERSION 2.8...3.21 )
project (run_pe)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

message (STATUS "parser_dir='${PECONV_DIR}'")
message (STATUS "parser_lib='${PECONV_LIB}'")

include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
	run_pe.cpp
)

set (hdrs
	run_pe.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies( ${PROJECT_NAME} libpeconv)

if(PECONV_LIB_INSTALL)
	include(GNUInstallDirs)

	install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
