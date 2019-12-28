# TESTS
project(taetl-tests)

set(TEST_SRC
    test_main.cpp
    
    test_algorithm.cpp
    test_array.cpp
    test_array_constexpr.cpp
    test_definitions.cpp
    test_numeric.cpp
    test_string.cpp
    test_string_constexpr.cpp
    test_tuple.cpp
    test_type_traits.cpp
)
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TEST_SRC})
add_executable(${PROJECT_NAME} ${TEST_SRC})
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        tobanteAudio::etl
        tobanteAudio::CompilerWarnings 
        tobanteAudio::CodeCoverage 
        Catch2::Catch2
)

include(CTest)
include(Catch)
catch_discover_tests(${PROJECT_NAME})


