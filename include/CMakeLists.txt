project(tetl)

add_library(etl_header_only INTERFACE)
add_library(tetl::etl_headers ALIAS etl_header_only)

file(GLOB_RECURSE TETL_HEADER_FILES CONFIGURE_DEPENDS "*.hpp")

target_sources(etl_header_only
    INTERFACE
    FILE_SET HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}
    FILES ${TETL_HEADER_FILES}
)
