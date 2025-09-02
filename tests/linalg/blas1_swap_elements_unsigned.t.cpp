// SPDX-License-Identifier: BSL-1.0

#include "blas1_swap_elements.t.hpp"

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_index_type<unsigned char>());
    CHECK(test_index_type<unsigned short>());
    CHECK(test_index_type<unsigned int>());
    CHECK(test_index_type<unsigned long>());
    CHECK(test_index_type<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return EXIT_SUCCESS;
}
