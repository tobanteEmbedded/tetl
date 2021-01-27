add_library(compiler_warnings INTERFACE)
add_library(tobanteAudio::CompilerWarnings ALIAS compiler_warnings)

if(MSVC)
  target_compile_options(compiler_warnings INTERFACE /W3)
  if(TOBANTEAUDIO_ETL_BUILD_WERROR)
    target_compile_options(compiler_warnings INTERFACE /WX)
  endif(TOBANTEAUDIO_ETL_BUILD_WERROR)
else()
  if(TOBANTEAUDIO_ETL_BUILD_WERROR)
    target_compile_options(compiler_warnings INTERFACE -Werror)
  endif(TOBANTEAUDIO_ETL_BUILD_WERROR)

  # GCC & CLANG
  target_compile_options(
    compiler_warnings
    INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        # -Wsign-conversion
        # -Wconversion
        # -Wdouble-promotion
  )

  # GCC
  target_compile_options(
    compiler_warnings
    INTERFACE
    $<$<CXX_COMPILER_ID:GNU>:
        -Wmisleading-indentation
        -Wlogical-op
        -Wduplicated-branches
        -Wduplicated-cond
        -Wno-parentheses
        -Wno-sequence-point
    >
  )

  # CLANG
  target_compile_options(
    compiler_warnings
    INTERFACE
    $<$<CXX_COMPILER_ID:Clang>:
        -Wshadow-all
    >
  )
endif()