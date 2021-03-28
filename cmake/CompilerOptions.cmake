add_library(compiler_options INTERFACE)
add_library(tobanteAudio::CompilerOptions ALIAS compiler_options)

if(MSVC)
  target_compile_options(compiler_options INTERFACE "/permissive-" "/Zc:__cplusplus")
else()
  target_compile_options(compiler_options INTERFACE -fno-builtin)
  target_link_libraries(compiler_options INTERFACE -fno-builtin)
endif(MSVC)

# Sanitizers
set(SANITIZERS "")
# Address
if(TOBANTEAUDIO_ETL_BUILD_ASAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  list(APPEND SANITIZERS "address")
endif()

# Undefined
if(TOBANTEAUDIO_ETL_BUILD_UBSAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  list(APPEND SANITIZERS "undefined")
endif()

# Memory
if(TOBANTEAUDIO_ETL_BUILD_MSAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  list(APPEND SANITIZERS "memory")
endif()

# Thread
if(TOBANTEAUDIO_ETL_BUILD_TSAN AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  list(APPEND SANITIZERS "thread")
endif()


list(JOIN SANITIZERS "," LIST_OF_SANITIZERS)
if(LIST_OF_SANITIZERS)
  if(NOT "${LIST_OF_SANITIZERS}" STREQUAL "")
    target_compile_options(compiler_options INTERFACE -fsanitize=${LIST_OF_SANITIZERS} -O1 -g -fno-omit-frame-pointer)
    target_link_libraries(compiler_options INTERFACE -fsanitize=${LIST_OF_SANITIZERS} -O1 -g -fno-omit-frame-pointer)
  endif()
endif()
