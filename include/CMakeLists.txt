# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2022 Tobias Hienzsch
project(tetl)

add_library(tetl.etl INTERFACE)
add_library(tetl::etl ALIAS tetl.etl)

file(GLOB_RECURSE TETL_HEADER_FILES CONFIGURE_DEPENDS "*.hpp")

target_sources(tetl.etl
    INTERFACE
    FILE_SET HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}
    FILES ${TETL_HEADER_FILES}
)
