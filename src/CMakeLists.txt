# Name
project(taetl)

# Define library
set(TAETL_LIB taetl-lib)

add_library(${TAETL_LIB} INTERFACE)
add_library(tobanteAudio::etl ALIAS ${TAETL_LIB})

target_include_directories(${TAETL_LIB} INTERFACE ${PROJECT_SOURCE_DIR})
target_compile_features(${TAETL_LIB} INTERFACE cxx_std_17)
