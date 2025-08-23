project(tetl-module)

add_library(tetl.etl-module)
add_library(tetl::etl-module ALIAS tetl.etl-module)
target_link_libraries(tetl.etl-module PUBLIC tetl::etl)
target_sources(tetl.etl-module
    PUBLIC
    FILE_SET CXX_MODULES
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    FILES "etl.cpp"
)
