cmake_minimum_required ( VERSION 2.8 )
project ( peconv )

# modules:
set ( M_PECONV_LIB "libpeconv" )
set ( M_PECONV_TEST "test" )

# modules paths:
set ( PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_LIB}" CACHE PATH "PEConvLib main path" )
set ( TEST_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_TEST}" CACHE PATH "Test main path" )

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

