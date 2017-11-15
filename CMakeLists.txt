cmake_minimum_required ( VERSION 2.8 )
project ( peconv )

# modules:
set ( M_PECONV_LIB "libpeconv" )
set ( M_PECONV_TEST "test" )
set ( M_PE_UNMAPPER "pe_unmapper" )


# modules paths:
set ( PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_LIB}" CACHE PATH "PEConvLib main path" )
set ( TEST_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_TEST}" CACHE PATH "Test main path" )
set ( UNMAPPER_DIR "${CMAKE_SOURCE_DIR}/${M_PE_UNMAPPER}" CACHE PATH "PEUnmapper main path" )

# Add sub-directories
#
# libs
add_subdirectory ( libpeconv )
get_property ( PECONV_LOCATION TARGET libpeconv PROPERTY LOCATION)
set ( PECONV_LIB ${PECONV_LOCATION} CACHE FILE "PEConvLib library path" )

# executables
add_subdirectory ( test )

# dependencies
add_dependencies ( test libpeconv )

# executables
add_subdirectory ( pe_unmapper )

# dependencies
add_dependencies ( pe_unmapper libpeconv )