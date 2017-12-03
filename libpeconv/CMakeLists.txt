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
	src/imports_loader.cpp
	src/pe_loader.cpp
	src/exports_lookup.cpp
	src/function_resolver.cpp
	src/hooks.cpp
	src/process_explorer.cpp
)

set (hdrs
	include/peconv.h
	include/peconv/pe_raw_to_virtual.h
	include/peconv/pe_virtual_to_raw.h
	include/peconv/relocate.h
	include/peconv/util.h
	include/peconv/pe_hdrs_helper.h
	include/peconv/module_helper.h
	include/peconv/remote_pe_reader.h
	include/peconv/imports_loader.h
	include/peconv/pe_loader.h
	include/peconv/exports_lookup.h
	include/peconv/function_resolver.h
	include/peconv/hooks.h
	include/peconv/process_explorer.h
)

add_library ( ${PROJECT_NAME} STATIC ${hdrs} ${srcs} )
