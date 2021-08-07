add_library(compiler_options INTERFACE)
add_library(tobanteEmbedded::CompilerOptions ALIAS compiler_options)

if(MSVC)
  target_compile_options(compiler_options INTERFACE "/permissive-" "/Zc:__cplusplus")
else()
  target_compile_options(compiler_options INTERFACE -fno-builtin)
  target_link_libraries(compiler_options INTERFACE -fno-builtin)
endif(MSVC)

if(TETL_BUILD_ASAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(compiler_options INTERFACE -fsanitize=address -O1 -g -fno-omit-frame-pointer)
  target_link_libraries(compiler_options INTERFACE -fsanitize=address -O1 -g -fno-omit-frame-pointer)
endif()

if(TETL_BUILD_UBSAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(compiler_options INTERFACE -fsanitize=undefined -fno-sanitize-recover=undefined -O1 -g -fno-omit-frame-pointer)
  target_link_libraries(compiler_options INTERFACE -fsanitize=undefined -fno-sanitize-recover=undefined -O1 -g -fno-omit-frame-pointer)
endif()