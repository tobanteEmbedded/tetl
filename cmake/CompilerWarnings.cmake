add_library(compiler_warnings INTERFACE)
add_library(tobanteAudio::CompilerWarnings ALIAS compiler_warnings)

if(MSVC)
  target_compile_options(compiler_warnings INTERFACE /W4 "/permissive-")
else()
  target_compile_options(compiler_warnings INTERFACE 
    -Wall
    -Wextra
    -Wpedantic
    -Wold-style-cast
    -Wnull-dereference
    -Wuseless-cast
  )
endif()