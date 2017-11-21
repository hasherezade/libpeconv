cmake_minimum_required (VERSION 2.8)
project (tests)

#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

message (STATUS "parser_dir='${PECONV_DIR}'")
message (STATUS "parser_lib='${PECONV_LIB}'")

include_directories ( ${PECONV_DIR} )

set (srcs
	main.cpp
	file_helper.cpp
	test_loading.cpp
	test_loading_imps.cpp
)

set (hdrs
	file_helper.h
	test_loading.h
	test_loading_imps.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies( ${PROJECT_NAME} libpeconv)

enable_testing()

# 0) does the application run
add_test (TestRuns tests)

# 1) compare relocations applied by the loader with relocations applied by Windows Loader
add_test (TestLoadSelf tests 1)
set_tests_properties (TestLoadSelf PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")

# 2) load the image of the current process from the disk and deploy it:
add_test (TestDeploySelf tests 2)
set_tests_properties (TestDeploySelf PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")