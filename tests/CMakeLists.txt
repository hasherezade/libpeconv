cmake_minimum_required (VERSION 2.8)
project (tests)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

message (STATUS "parser_dir='${PECONV_DIR}'")
message (STATUS "parser_lib='${PECONV_LIB}'")

include_directories ( ${PECONV_DIR} )

set (srcs
	main.cpp
	file_helper.cpp
)

set (hdrs
	file_helper.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies( ${PROJECT_NAME} libpeconv)

enable_testing()

# 0) does the application run
add_test (TestRuns tests)

# 1) compare relocations applied by the loader with relocations applied by Windows Loader
add_test (TestLoads tests 1)
set_tests_properties (TestLoads PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
