# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(tetl-module)

function(tetl_add_module_target _target)
    add_library(${_target})
    target_link_libraries(${_target} PUBLIC tetl::etl)
    target_sources(${_target}
        PUBLIC
        FILE_SET CXX_MODULES
        BASE_DIRS "${CMAKE_SOURCE_DIR}/src"
        FILES "${CMAKE_SOURCE_DIR}/src/etl.cpp"
    )
endfunction()
