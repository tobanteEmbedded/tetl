# TESTS
project(taetl-tests)

# ARRAY
add_executable(taetl-test-array test_array.cpp)
target_link_libraries(taetl-test-array tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_array taetl-test-array)

# DEFINITIONS
add_executable(taetl-test-definitions test_definitions.cpp)
target_link_libraries(taetl-test-definitions tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_definitions taetl-test-definitions)

# STRING
add_executable(taetl-test-strings test_string.cpp)
target_link_libraries(taetl-test-strings tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_strings taetl-test-strings)
# STRING CONSTEXPR
add_executable(taetl-test-constexpr_string test_string_constexpr.cpp)
target_link_libraries(taetl-test-constexpr_string tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_string_constexpr taetl-test-constexpr_string)