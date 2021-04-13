add_library(coverage_config INTERFACE)
add_library(tobanteEmbedded::CodeCoverage ALIAS coverage_config)

if(TETL_BUILD_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  target_compile_options(coverage_config INTERFACE -O0 -g --coverage)
  target_link_libraries(coverage_config INTERFACE --coverage)
endif()

if(TETL_BUILD_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_compile_options(coverage_config INTERFACE
    -O0 -g
    -ftest-coverage
    -fcoverage-mapping
    -fprofile-arcs
    -fprofile-instr-generate
  )
  target_link_libraries(coverage_config INTERFACE --coverage)
endif()