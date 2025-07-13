project(tetl-module)

add_library(tetl-module)
target_link_libraries(tetl-module PUBLIC tetl::etl_headers)
target_sources(tetl-module
    PUBLIC
    FILE_SET CXX_MODULES
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    FILES
        "etl.cpp"

        "src/algorithm.cpp"
        "src/array.cpp"
        "src/bit.cpp"
        "src/bitset.cpp"
        "src/cctype.cpp"
        "src/cfloat.cpp"
        "src/charconv.cpp"
        "src/chrono.cpp"
        "src/cmath.cpp"
        "src/compare.cpp"
        "src/complex.cpp"
        "src/concepts.cpp"
        "src/cstddef.cpp"
        "src/cstdint.cpp"
        "src/cstdlib.cpp"
        "src/exception.cpp"
        "src/flat_set.cpp"
        "src/functional.cpp"
        "src/inplace_vector.cpp"
        "src/iterator.cpp"
        "src/limits.cpp"
        "src/linalg.cpp"
        "src/mdarray.cpp"
        "src/mdspan.cpp"
        "src/memory.cpp"
        "src/numbers.cpp"
        "src/numeric.cpp"
        "src/optional.cpp"
        "src/random.cpp"
        "src/ranges.cpp"
        "src/ratio.cpp"
        "src/span.cpp"
        "src/string_view.cpp"
        "src/string.cpp"
        "src/strings.cpp"
        "src/system_error.cpp"
        "src/tuple.cpp"
        "src/type_traits.cpp"
        "src/utility.cpp"
        "src/variant.cpp"
        "src/vector.cpp"
)
