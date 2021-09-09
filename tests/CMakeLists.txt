project(etl-tests)

add_library(testing_defs INTERFACE)
target_compile_definitions(testing_defs INTERFACE TETL_DEBUG=1 TETL_ENABLE_USER_CONFIG_HEADER_INCLUDE=1)
target_include_directories(testing_defs INTERFACE ${PROJECT_SOURCE_DIR})
target_link_libraries(testing_defs
    INTERFACE
        tobanteEmbedded::etl
        tobanteEmbedded::CompilerOptions
        tobanteEmbedded::CompilerWarnings
        tobanteEmbedded::CodeCoverage
)

function(tetl_add_test _header _target)
  set(options OPTIONAL WILL_FAIL)
  cmake_parse_arguments(TETL_ADD_TEST_PREFIX "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
  add_executable("test_${_header}_${_target}" "${_target}.t.cpp")
  add_test(NAME "test_${_header}_${_target}" COMMAND "test_${_header}_${_target}")
  target_include_directories(test_${_header}_${_target} PRIVATE ${PROJECT_SOURCE_DIR}/..)
  target_link_libraries("test_${_header}_${_target}" PRIVATE testing_defs)
  set_tests_properties("test_${_header}_${_target}" PROPERTIES WILL_FAIL ${TETL_ADD_TEST_PREFIX_WILL_FAIL})
endfunction()



add_subdirectory("algorithm")
add_subdirectory("array")
add_subdirectory("bit")
add_subdirectory("bitset")
add_subdirectory("cctype")
add_subdirectory("cfloat")
add_subdirectory("charconv")
add_subdirectory("chrono")
add_subdirectory("cmath")
add_subdirectory("complex")
add_subdirectory("concepts")
add_subdirectory("cstdarg")
add_subdirectory("cstddef")
add_subdirectory("cstdint")
add_subdirectory("cstdlib")
add_subdirectory("cstring")
add_subdirectory("exception")
add_subdirectory("expected")
add_subdirectory("format")
add_subdirectory("functional")
add_subdirectory("ios")
add_subdirectory("iterator")
add_subdirectory("limits")
add_subdirectory("memory")
add_subdirectory("mutex")
add_subdirectory("numbers")
add_subdirectory("numeric")
add_subdirectory("optional")
add_subdirectory("ratio")
add_subdirectory("scope")
add_subdirectory("set")
add_subdirectory("span")
add_subdirectory("stack")
add_subdirectory("stdexcept")
add_subdirectory("string")
add_subdirectory("string_view")
add_subdirectory("tuple")
add_subdirectory("type_traits")
add_subdirectory("utility")
add_subdirectory("variant")
add_subdirectory("vector")
add_subdirectory("version")

add_subdirectory("experimental/freertos")
add_subdirectory("experimental/meta")
add_subdirectory("experimental/net")
add_subdirectory("experimental/stm32")
add_subdirectory("experimental/strong_type")
add_subdirectory("experimental/testing")



