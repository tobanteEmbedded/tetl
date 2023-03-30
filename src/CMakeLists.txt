cmake_minimum_required(VERSION 3.26)
project(tetl-module LANGUAGES CXX)

if(NOT TETL_BUILD_MODULE)
    return()
endif()

set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API "2182bf5c-ef0d-489a-91da-49dbc3090d2a")
set(CMake_TEST_CXXModules_UUID "a246741c-d067-4019-a8fb-3d16b0c9d1d3")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_DYNDEP 1)

add_library(tetl-module STATIC)
add_library(tetl::etl-module ALIAS tetl-module)

target_link_libraries(tetl-module
	PUBLIC
        tetl::etl
)

target_sources(tetl-module PUBLIC
	FILE_SET CXX_MODULES
	BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
	FILES
		etl.cpp
)
