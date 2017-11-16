cmake_minimum_required ( VERSION 2.8 )
project ( peconv )

# modules:
set ( M_PECONV_LIB "libpeconv" )
set ( M_PECONV_TEST "test" )
set ( M_PE_UNMAPPER "pe_unmapper" )
set ( M_RUN_PE "run_pe" )

# modules paths:
set ( PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_LIB}" CACHE PATH "PEConvLib main path" )
set ( TEST_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_TEST}" CACHE PATH "Test main path" )
set ( UNMAPPER_DIR "${CMAKE_SOURCE_DIR}/${M_PE_UNMAPPER}" CACHE PATH "PEUnmapper main path" )
set ( RUNPE_DIR "${CMAKE_SOURCE_DIR}/${M_RUN_PE}" CACHE PATH "RunPE main path" )

# Add sub-directories
#
# libs
add_subdirectory ( libpeconv )
get_property ( PECONV_LOCATION TARGET libpeconv PROPERTY LOCATION)
set ( PECONV_LIB ${PECONV_LOCATION} CACHE FILE "PEConvLib library path" )

# executables
add_subdirectory ( test )
add_subdirectory ( pe_unmapper )
add_subdirectory ( run_pe )

# dependencies
add_dependencies ( test libpeconv )
add_dependencies ( pe_unmapper libpeconv )
add_dependencies ( run_pe libpeconv )