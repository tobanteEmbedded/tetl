# Name
project(taetl)

add_library(${PROJECT_NAME} INTERFACE)
add_library(tobanteAudio::etl ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} INTERFACE ${PROJECT_SOURCE_DIR})
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_17)
