cmake_minimum_required ( VERSION 2.8 )
project ( libpeconv )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

include_directories (
  include
)

set (srcs
	src/pe_hdrs_helper.cpp
	src/pe_raw_to_virtual.cpp
	src/pe_virtual_to_raw.cpp
	src/relocate.cpp
	src/util.cpp
	src/module_helper.cpp
	src/remote_pe_reader.cpp
	src/load_imports.cpp
)

set (hdrs
	peconv.h
	include/pe_raw_to_virtual.h
	include/pe_virtual_to_raw.h
	include/relocate.h
	include/util.h
	include/pe_hdrs_helper.h
	include/module_helper.h
	include/remote_pe_reader.h
	include/load_imports.h
)

add_library ( ${PROJECT_NAME} STATIC ${hdrs} ${srcs} )
