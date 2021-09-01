project(etl-tests)

add_library(testing_defs INTERFACE)
target_compile_definitions(testing_defs INTERFACE TETL_ENABLE_USER_CONFIG_HEADER_INCLUDE=1)
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
  target_compile_definitions(test_${_header}_${_target} PRIVATE TETL_DEBUG=1 TETL_ENABLE_USER_CONFIG_HEADER_INCLUDE=1)
  target_include_directories(test_${_header}_${_target} PRIVATE ${PROJECT_SOURCE_DIR}/..)
  target_link_libraries("test_${_header}_${_target}" PRIVATE testing_defs)
  set_tests_properties("test_${_header}_${_target}" PROPERTIES WILL_FAIL ${TETL_ADD_TEST_PREFIX_WILL_FAIL})
endfunction()

add_executable(${PROJECT_NAME})
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
target_sources(${PROJECT_NAME}
    PRIVATE
        algorithm/test_algorithm_01.cpp
        algorithm/test_algorithm_02.cpp
        algorithm/test_algorithm_03.cpp

        test_format.cpp
        test_iterator.cpp
        test_map.cpp
        test_memory.cpp
        test_numeric.cpp
        test_optional.cpp
        test_span.cpp
        test_string.cpp
        test_string_view.cpp
        test_type_traits.cpp
        test_utility.cpp
        test_variant.cpp
        test_vector.cpp

        _strings/test_conversion.cpp

        experimental/dsp/test_dsp.cpp

        experimental/meta/test_meta_algorithm.cpp
        experimental/meta/test_meta_traits.cpp
        experimental/meta/test_meta_types.cpp

        experimental/net/test_buffer.cpp
        experimental/net/test_byte_order.cpp

        experimental/freertos/test_task.cpp
        experimental/freertos/test_stream_buffer.cpp
        experimental/freertos/test_queue.cpp

        experimental/stm32/test_gpio.cpp
        experimental/stm32/test_interrupt.cpp

        experimental/strong_type/test_strong_type.cpp

        experimental/mcp23017/test_mcp23017.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE testing_defs Catch2WithMain)


add_executable(${PROJECT_NAME}_testing
    experimental/testing/test_main.cpp
    experimental/testing/test_test_case.cpp
)
add_test(NAME ${PROJECT_NAME}_testing COMMAND ${PROJECT_NAME}_testing)
target_link_libraries(${PROJECT_NAME}_testing
    PRIVATE
        tobanteEmbedded::etl
        tobanteEmbedded::CompilerOptions
        tobanteEmbedded::CompilerWarnings
        tobanteEmbedded::CodeCoverage
)


add_subdirectory(array)
add_subdirectory(bit)
add_subdirectory(bitset)
add_subdirectory(cctype)
add_subdirectory(charconv)
add_subdirectory(chrono)
add_subdirectory(cmath)
add_subdirectory(complex)
add_subdirectory(concepts)
add_subdirectory(cstdarg)
add_subdirectory(cstddef)
add_subdirectory(cstdint)
add_subdirectory(cstdlib)
add_subdirectory(cstring)
add_subdirectory(exception)
add_subdirectory(expected)
add_subdirectory(functional)
add_subdirectory(ios)
add_subdirectory(limits)
add_subdirectory(mutex)
add_subdirectory(numbers)
add_subdirectory(numeric)
add_subdirectory(ratio)
add_subdirectory(scope)
add_subdirectory(set)
add_subdirectory(stack)
add_subdirectory(stdexcept)
add_subdirectory(tuple)
add_subdirectory(version)
