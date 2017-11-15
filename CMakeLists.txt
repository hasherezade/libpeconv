cmake_minimum_required ( VERSION 2.8 )
project ( peconv )

# modules:
set ( M_PECONV_LIB "libpeconv" )
set ( M_PECONV_DEMO "demo" )

# modules paths:
set ( PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_LIB}" CACHE PATH "PEConvLib main path" )
set ( DEMO_DIR "${CMAKE_SOURCE_DIR}/${M_PECONV_DEMO}" CACHE PATH "Demo main path" )

# Add sub-directories
#
# libs
add_subdirectory ( libpeconv )
get_property ( PECONV_LOCATION TARGET libpeconv PROPERTY LOCATION)
set ( PECONV_LIB ${PECONV_LOCATION} CACHE FILE "PEConvLib library path" )

# executables
add_subdirectory ( demo )

# dependencies
add_dependencies ( demo libpeconv )

