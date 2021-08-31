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

function(tetl_add_test _group _target)
  add_executable("test_${_group}_${_target}" "${_target}.t.cpp")
  add_test(NAME "test_${_group}_${_target}" COMMAND "test_${_group}_${_target}")
  target_compile_definitions(test_${_group}_${_target} PRIVATE TETL_ENABLE_USER_CONFIG_HEADER_INCLUDE=1)
  target_include_directories(test_${_group}_${_target} PRIVATE ${PROJECT_SOURCE_DIR}/..)
  target_link_libraries("test_${_group}_${_target}" PRIVATE testing_defs)
endfunction()

add_executable(${PROJECT_NAME})
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
target_sources(${PROJECT_NAME}
    PRIVATE
        assert_handler.cpp

        algorithm/test_algorithm_01.cpp
        algorithm/test_algorithm_02.cpp
        algorithm/test_algorithm_03.cpp

        test_array.cpp
        test_bit.cpp
        test_bitset.cpp
        test_cctype.cpp
        test_charconv.cpp
        test_chrono.cpp
        test_complex.cpp
        test_cstdarg.cpp
        test_cstddef.cpp
        test_cstdint.cpp
        test_cstdio.cpp
        test_cstdlib.cpp
        test_cstring.cpp
        test_concepts.cpp
        test_ctime.cpp
        test_cwchar.cpp
        test_expected.cpp
        test_exception.cpp
        test_format.cpp
        test_functional.cpp
        test_ios.cpp
        test_iterator.cpp
        test_map.cpp
        test_memory.cpp
        test_mutex.cpp
        test_numbers.cpp
        test_numeric.cpp
        test_optional.cpp
        test_ratio.cpp
        test_scope.cpp
        test_set.cpp
        test_span.cpp
        test_stack.cpp
        test_stdexcept.cpp
        test_string.cpp
        test_string_view.cpp
        test_tuple.cpp
        test_type_traits.cpp
        test_utility.cpp
        test_variant.cpp
        test_vector.cpp
        test_version.cpp

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


add_subdirectory(cmath)
add_subdirectory(limits)
add_subdirectory(numeric)
