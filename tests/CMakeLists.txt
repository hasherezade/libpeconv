cmake_minimum_required ( VERSION 3.0 )
project (tests)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

message (STATUS "parser_dir='${PECONV_DIR}'")
message (STATUS "parser_lib='${PECONV_LIB}'")

include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
	test_loading.cpp
	test_loading_imps.cpp
	test_crackme_f4_3.cpp
	test_hooking_imps.cpp
	test_crackme_f4_6.cpp
	test_load_ntdll.cpp
	test_replacing_func.cpp
	test_delayed_imps.cpp
	test_imp_list.cpp
	test_hooking_local.cpp
	test_peb_lookup.cpp
	test_imports_mix.cpp
	test_found_base.cpp
	test_fix_dotnet.cpp
	test_format_detect.cpp
	test_tls_callbacks.cpp
)

set (hdrs
	test_loading.h
	test_loading_imps.h
	test_crackme_f4_3.h
	test_hooking_imps.h
	test_crackme_f4_6.h
	test_load_ntdll.h
	test_replacing_func.h
	test_delayed_imps.h
	test_imp_list.h
	test_hooking_local.h
	test_peb_lookup.h
	test_imports_mix.h
	test_found_base.h
	test_fix_dotnet.h
	test_format_detect.h
	test_tls_callbacks.h
	resource.h
	shellcodes.h
	shellc32.h
	shellc64.h
)

set (rsrc
	resource.rc
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} )
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies( ${PROJECT_NAME} libpeconv test_case1 test_case3 )

#add the application that will be used for tests:
add_subdirectory ( test_case1 )
add_subdirectory ( test_case3 )
add_subdirectory ( test_case4 )
add_subdirectory ( test_case5 )
add_subdirectory ( test_case6 )

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

enable_testing()

# 0) does the application run
add_test (TestRuns ${CMAKE_INSTALL_PREFIX}/tests)

# 1) compare relocations applied by the loader with relocations applied by Windows Loader
add_test (TestLoadSelf ${CMAKE_INSTALL_PREFIX}/tests 1)
set_tests_properties (TestLoadSelf PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")

# 2) load the image of the current process from the disk and deploy it:
add_test (TestDeploySelf ${CMAKE_INSTALL_PREFIX}/tests 2)
set_tests_properties (TestDeploySelf PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")

#only for 32bit:
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
	# 3) Deploys a brutforcer for FlareOn4 Crackme 3
	add_test (TestCrackmeF4_3 ${CMAKE_INSTALL_PREFIX}/tests 3)
	set_tests_properties (TestCrackmeF4_3 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
endif()

# 4) load the image of the current process from the disk and deploy it. Imports are resolved by exports lookup (custom recolver).
add_test (TestDeploySelfExpResolver ${CMAKE_INSTALL_PREFIX}/tests 4)
set_tests_properties (TestDeploySelfExpResolver PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestDeploySelfExpResolver PROPERTIES FAIL_REGULAR_EXPRESSION "Loaded proc is not matching the default one!")

# 5) test hooking a test_case1 application
add_test (TestHookMessageBox ${CMAKE_INSTALL_PREFIX}/tests 5 ${CMAKE_INSTALL_PREFIX}/test_case1.exe )
set_tests_properties (TestHookMessageBox PROPERTIES PASS_REGULAR_EXPRESSION "Hooking test passed")

#only for 64bit:
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	# 6) Solve FlareOn2017 Challenge6
	add_test (TestCrackmeF4_6 ${CMAKE_INSTALL_PREFIX}/tests 6 ${CMAKE_INSTALL_PREFIX}/payload.dll )
	set_tests_properties (TestCrackmeF4_6 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
endif()

# 8) Test replacing and redirecting functions
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_test (TestReplaceFunc64 ${CMAKE_INSTALL_PREFIX}/tests 8 ${CMAKE_INSTALL_PREFIX}/test_case3_64.exe )
	set_tests_properties (TestReplaceFunc64 PROPERTIES PASS_REGULAR_EXPRESSION "Passed!")
	set_tests_properties (TestReplaceFunc64 PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")
else()
	add_test (TestReplaceFunc32 tests 8 ${CMAKE_INSTALL_PREFIX}/test_case3_32.exe )
	set_tests_properties (TestReplaceFunc32 PROPERTIES PASS_REGULAR_EXPRESSION "Passed!")
	set_tests_properties (TestReplaceFunc32 PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")
endif()

# 9) test replacing Delay-Load Imports
add_test (TestDelayedImps ${CMAKE_INSTALL_PREFIX}/tests 9 ${CMAKE_INSTALL_PREFIX}/test_case4.exe )
set_tests_properties (TestDelayedImps PROPERTIES PASS_REGULAR_EXPRESSION "Hooking test passed")
set_tests_properties (TestDelayedImps PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 11) test redirecting local functions (and undoing the redirection)
add_test (TestLocalRedirect tests 11 )
set_tests_properties (TestLocalRedirect PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestLocalRedirect PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 12) test PEB lookup
add_test (TestPEBLookup ${CMAKE_INSTALL_PREFIX}/tests 12 )
set_tests_properties (TestPEBLookup PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestPEBLookup PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 13) test mixed imports
add_test (TestMixImp ${CMAKE_INSTALL_PREFIX}/tests 13 ${CMAKE_INSTALL_PREFIX}/test_case5_exe.exe )
set_tests_properties (TestMixImp PROPERTIES PASS_REGULAR_EXPRESSION "Test Case 5 finished, checks: a0caa919")
set_tests_properties (TestMixImp PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 14) test finding base
add_test (TestFindBase ${CMAKE_INSTALL_PREFIX}/tests 14 ${CMAKE_INSTALL_PREFIX}/test_case5_exe.exe )
set_tests_properties (TestFindBase PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestFindBase PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 15) test finding jumps
add_test (TestFindJumpToDotNet ${CMAKE_INSTALL_PREFIX}/tests 15 )
set_tests_properties (TestFindJumpToDotNet PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestFindJumpToDotNet PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 16.1) test detect virtual/raw: 32
add_test (TestDetectMode32 tests 16 ${CMAKE_INSTALL_PREFIX}/test_case3_32.exe )
set_tests_properties (TestDetectMode32 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestDetectMode32 PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")

# 16.2) test detect virtual/raw: 64
add_test (TestDetectMode64 tests 16 ${CMAKE_INSTALL_PREFIX}/test_case3_64.exe )
set_tests_properties (TestDetectMode64 PROPERTIES PASS_REGULAR_EXPRESSION "Test passed")
set_tests_properties (TestDetectMode64 PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")


# 17) test running TLS callbacks
add_test (TestTLSCallbacks 17 ${CMAKE_INSTALL_PREFIX}/test_case6.exe )
set_tests_properties (TestTLSCallbacks PROPERTIES PASS_REGULAR_EXPRESSION "Password: NR7YcqGFUn0")
set_tests_properties (TestTLSCallbacks PROPERTIES FAIL_REGULAR_EXPRESSION "Failed")
