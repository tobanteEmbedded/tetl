# TESTS
project(taetl-tests)

# ARRAY
add_executable(taetl-test-array test_array.cpp)
target_compile_features(taetl-test-array PUBLIC cxx_std_17)
target_link_libraries(taetl-test-array tobanteAudio::CompilerWarnings tobanteAudio::etl)
add_test(Test_All taetl-test-array)

# DENITIONS
add_executable(taetl-test-definitions test_definitions.cpp)
target_compile_features(taetl-test-definitions PUBLIC cxx_std_17)
target_link_libraries(taetl-test-definitions tobanteAudio::CompilerWarnings tobanteAudio::etl)
add_test(Test_All taetl-test-definitions)

# STRING
add_executable(taetl-test-strings test_string.cpp)
target_compile_features(taetl-test-strings PUBLIC cxx_std_17)
target_link_libraries(taetl-test-strings tobanteAudio::CompilerWarnings tobanteAudio::etl)
add_test(Test_All taetl-test-strings)