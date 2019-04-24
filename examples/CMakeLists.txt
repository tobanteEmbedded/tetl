project(taetl-examples)

# Define executable
add_executable(${PROJECT_NAME} main.cpp)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_link_libraries(${PROJECT_NAME} tobanteAudio::CompilerWarnings tobanteAudio::etl)
