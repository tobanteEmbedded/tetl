# Name
project(taetl)

# Define library
set(TAETL_LIB taetl-lib)
set(TAETL_HEADERS
    taetl/array.h
    taetl/definitions.h
    taetl/hardware.h
    taetl/type_traits.h
    taetl/vector.h
    taetl/version.h
)

add_library(${TAETL_LIB} INTERFACE)
add_library(tobanteAudio::etl ALIAS ${TAETL_LIB})

target_include_directories(${TAETL_LIB} INTERFACE ${PROJECT_SOURCE_DIR})
target_compile_features(${TAETL_LIB} INTERFACE cxx_std_17)
