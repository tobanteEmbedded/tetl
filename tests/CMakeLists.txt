# TESTS
project(taetl-tests)

set(TEST_SRC
    test_main.cpp
    
    test_algorithm.cpp
    test_array.cpp
    test_bit.cpp
    test_bitset.cpp
    test_definitions.cpp
    test_numeric.cpp
    test_map.cpp
    test_string.cpp
    test_string_constexpr.cpp
    test_tuple.cpp
    test_type_traits.cpp
    test_vector.cpp

    experimental/net/test_buffer.cpp
    experimental/net/test_byte_order.cpp

    experimental/rtos/test_queue.cpp
    
    experimental/stm32/test_gpio.cpp

    experimental/mcp23017/test_mcp23017.cpp
)
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TEST_SRC})
add_executable(${PROJECT_NAME} ${TEST_SRC})
# set_target_properties(${PROJECT_NAME} PROPERTIES CXX_CLANG_TIDY "${DO_CLANG_TIDY}")
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        tobanteAudio::etl
        tobanteAudio::CompilerOptions
        tobanteAudio::CompilerWarnings 
        tobanteAudio::CodeCoverage 
        Catch2::Catch2
)

catch_discover_tests(${PROJECT_NAME})


