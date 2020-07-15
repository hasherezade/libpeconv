cmake_minimum_required ( VERSION 2.8 )

project ( peconv )
option(PECONV_BUILD_TESTING "enable testing for peconv" ON)
option(PECONV_LIB_INSTALL "Enable install" ON )

# modules:
set ( M_PECONV_LIB "libpeconv" )
set ( M_PECONV_TEST "tests" )
set ( M_PE_UNMAPPER "pe_unmapper" )
set ( M_RUN_PE "run_pe" )

# modules paths:
set ( PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_LIB}" CACHE PATH "PEConvLib main path" )
set ( UNMAPPER_DIR "${CMAKE_SOURCE_DIR}/${M_PE_UNMAPPER}" CACHE PATH "PEUnmapper main path" )
set ( RUNPE_DIR "${CMAKE_SOURCE_DIR}/${M_RUN_PE}" CACHE PATH "RunPE main path" )

# Add sub-directories
#
# libs
add_subdirectory ( libpeconv )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE PATH "PEConvLib library path" )

#demos:
add_subdirectory ( pe_unmapper )
add_dependencies ( pe_unmapper libpeconv )

add_subdirectory ( run_pe )
add_dependencies ( run_pe libpeconv )

# Setup testing
if(PECONV_BUILD_TESTING)
	enable_testing()

	# executables
	add_subdirectory ( ${M_PECONV_TEST} )
	add_dependencies ( ${M_PECONV_TEST} libpeconv )
endif()
