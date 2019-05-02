# TESTS
project(taetl-tests)

# MICROCATCH
set(MICROCATCH microcatch)
add_library(${MICROCATCH} INTERFACE)
add_library(tobanteAudio::MicroCatch ALIAS ${MICROCATCH})
target_include_directories(${MICROCATCH} INTERFACE ${PROJECT_SOURCE_DIR})
target_compile_features(${MICROCATCH} INTERFACE cxx_std_17)


# ALGORITHM
add_executable(taetl-test-algorithm test_algorithm.cpp)
target_link_libraries(taetl-test-algorithm 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_algorithm taetl-test-algorithm)

# ARRAY
add_executable(taetl-test-array test_array.cpp)
target_link_libraries(taetl-test-array 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_array taetl-test-array)
# ARRAY CONSTEXPR
add_executable(taetl-test-array_constexpr test_array_constexpr.cpp)
target_link_libraries(taetl-test-array_constexpr 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_array_constexpr taetl-test-array_constexpr)

# DEFINITIONS
add_executable(taetl-test-definitions test_definitions.cpp)
target_link_libraries(taetl-test-definitions 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_definitions taetl-test-definitions)

# NUMERIC
add_executable(taetl-test-numeric test_numeric.cpp)
target_link_libraries(taetl-test-numeric 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_numeric taetl-test-numeric)

# STRING
add_executable(taetl-test-strings test_string.cpp)
target_link_libraries(taetl-test-strings 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_strings taetl-test-strings)
# STRING CONSTEXPR
add_executable(taetl-test-constexpr_string test_string_constexpr.cpp)
target_link_libraries(taetl-test-constexpr_string 
    tobanteAudio::CompilerWarnings 
    tobanteAudio::CodeCoverage 
    tobanteAudio::MicroCatch 
    tobanteAudio::etl
)
add_test(Test_string_constexpr taetl-test-constexpr_string)