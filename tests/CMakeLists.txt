# TESTS
project(taetl-tests)

# ARRAY
add_executable(taetl-test-array array.cpp)
target_compile_features(taetl-test-array PUBLIC cxx_std_17)
target_link_libraries(taetl-test-array tobanteAudio::CompilerWarnings tobanteAudio::etl)

add_test(Test_All  taetl-test-array)