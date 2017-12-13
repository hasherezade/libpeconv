cmake_minimum_required (VERSION 2.8)
project (tests)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

message (STATUS "parser_dir='${PECONV_DIR}'")
message (STATUS "parser_lib='${PECONV_LIB}'")

include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
	file_helper.cpp
	resource_helper.cpp
	test_loading.cpp
	test_loading_imps.cpp
	test_crackme_f4_3.cpp
	test_hooking_imps.cpp
	test_crackme_f4_6.cpp
)

set (hdrs
	file_helper.h
	resource_helper.h
	test_loading.h
	test_loading_imps.h
	test_crackme_f4_3.h
	test_hooking_imps.h
	test_crackme_f4_6.h
	resource.h
)

set (rsrc
    resource.rc
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} )
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies( ${PROJECT_NAME} libpeconv test_case1)

#add the application that will be used for tests:
add_subdirectory ( test_case1 )

enable_testing()

# 0) does the application run
add_test (TestRuns tests)

# 1) compare relocations applied by the loader with relocations applied by Windows Loader
add_test (TestLoadSelf tests 1)
set_tests_properties (TestLoadSelf PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")

# 2) load the image of the current process from the disk and deploy it:
add_test (TestDeploySelf tests 2)
set_tests_properties (TestDeploySelf PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")

#only for 32bit:
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
	# 3) Deploys a brutforcer for FlareOn4 Crackme 3
	add_test (TestCrackmeF4_3 tests 3)
	set_tests_properties (TestCrackmeF4_3 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
endif()

# 4) load the image of the current process from the disk and deploy it. Imports are resolved by exports lookup (custom recolver).
add_test (TestDeploySelfExpResolver tests 4)
set_tests_properties (TestDeploySelfExpResolver PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestDeploySelfExpResolver PROPERTIES FAIL_REGULAR_EXPRESSION "Loaded proc is not matching the default one!")

# 5) test hooking a test_case1 application
add_test (TestHookMessageBox tests 5 "C://tests//test_case1.exe")
set_tests_properties (TestHookMessageBox PROPERTIES PASS_REGULAR_EXPRESSION "Hooking test passed")

#only for 64bit:
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	# 6) Solve FlareOn2017 Challenge6
	add_test (TestCrackmeF4_6 tests 6)
	set_tests_properties (TestCrackmeF4_6 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
endif()
