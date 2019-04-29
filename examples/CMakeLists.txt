# EXAMPLES
project(taetl-examples)

# ALGORITHM
add_executable(taetl-example-algorithm algorithm.cpp)
target_link_libraries(taetl-example-algorithm tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_Examples_algorithm taetl-example-algorithm)

# ARRAY
add_executable(taetl-example-array array.cpp)
target_link_libraries(taetl-example-array tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_Examples_array taetl-example-array)

# NUMERIC
add_executable(taetl-example-numeric numeric.cpp)
target_link_libraries(taetl-example-numeric tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_Examples_numeric taetl-example-numeric)

# STRING
add_executable(taetl-example-strings string.cpp)
target_link_libraries(taetl-example-strings tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_Examples_strings taetl-example-strings)

# TYPE TRAITS
add_executable(taetl-example-type_traits type_traits.cpp)
target_link_libraries(taetl-example-type_traits tobanteAudio::CompilerWarnings tobanteAudio::CodeCoverage tobanteAudio::etl)
add_test(Test_Examples_type_traits taetl-example-type_traits)
