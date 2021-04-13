add_library(compiler_warnings INTERFACE)
add_library(tobanteEmbedded::CompilerWarnings ALIAS compiler_warnings)

if (MSVC)
  if (TETL_BUILD_WERROR)
    target_compile_options(compiler_warnings INTERFACE /WX)
  endif (TETL_BUILD_WERROR)
  target_compile_options(compiler_warnings INTERFACE /W3)
else ()
  if (TETL_BUILD_WERROR)
    target_compile_options(compiler_warnings INTERFACE -Werror)
  endif (TETL_BUILD_WERROR)
    target_compile_options(compiler_warnings
      INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wcast-align
        -Wshadow
        -Wunused-parameter
        -Wnarrowing
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>: -Wshadow-all -Wdocumentation>
        $<$<CXX_COMPILER_ID:AppleClang>:  -Wno-poison-system-directories >
        $<$<CXX_COMPILER_ID:GNU>: -Wmisleading-indentation -Wlogical-op -Wduplicated-branches -Wduplicated-cond -Wno-parentheses -Wno-sequence-point >
    )
endif (MSVC)
