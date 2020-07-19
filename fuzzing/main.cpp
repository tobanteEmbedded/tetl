#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "etl/algorithm.hpp"

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size == 0) { return EXIT_SUCCESS; }
    auto value        = data[0];
    auto const* first = data + 1;
    auto const* last  = data + size;
    auto const* pos   = etl::find_if(
        first, last, [&](auto const item) { return item == value; });

    if (pos != last) { assert(*pos == value); }
    for (auto const* p = first; p != pos; ++p) { assert(*p != value); }

    return EXIT_SUCCESS;
}