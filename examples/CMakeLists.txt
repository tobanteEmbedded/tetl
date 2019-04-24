# EXAMPLES
project(taetl-examples)

# ARRAY
add_executable(taetl-example-array array.cpp)
target_compile_features(taetl-example-array PUBLIC cxx_std_17)
target_link_libraries(taetl-example-array tobanteAudio::CompilerWarnings tobanteAudio::etl)

# TYPE TRAITS
add_executable(taetl-example-type_traits type_traits.cpp)
target_compile_features(taetl-example-type_traits PUBLIC cxx_std_17)
target_link_libraries(taetl-example-type_traits tobanteAudio::CompilerWarnings tobanteAudio::etl)