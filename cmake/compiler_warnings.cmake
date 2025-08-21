add_library(tetl.compiler_warnings INTERFACE)
add_library(tetl::compiler_warnings ALIAS tetl.compiler_warnings)

if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    target_compile_options(tetl.compiler_warnings INTERFACE
        "/W3"
        "/wd4723" # potential divide by 0
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GCC")
    target_compile_options(tetl.compiler_warnings INTERFACE
        "-Wall"
        "-Wextra"
        "-Wpedantic"

        "-Wcast-align"
        "-Wcast-qual"
        "-Wdouble-promotion"
        "-Wduplicated-branches"
        "-Wduplicated-cond"
        "-Wlogical-op"
        "-Wmisleading-indentation"
        "-Wmissing-field-initializers"
        "-Wnarrowing"
        "-Woverloaded-virtual"
        "-Wreorder"
        "-Wshadow"
        "-Wsign-compare"
        "-Wsign-conversion"
        "-Wsign-promo"
        "-Wstrict-aliasing"
        "-Wswitch-enum"
        "-Wuninitialized"
        "-Wunreachable-code"
        "-Wunused-parameter"
        "-Wzero-as-null-pointer-constant"
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(tetl.compiler_warnings INTERFACE
        "-Weverything"

        "-Wno-c++98-compat-pedantic"
        "-Wno-c++20-compat"
        "-Wno-ctad-maybe-unsupported"
        "-Wno-float-equal"
        "-Wno-padded"
        "-Wno-unsafe-buffer-usage"
        "-Wno-unused-member-function"
        "-Wno-weak-vtables"
    )
endif ()
