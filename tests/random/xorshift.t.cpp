// SPDX-License-Identifier: BSL-1.0

#include <etl/random.hpp>

#include "testing/testing.hpp"

constexpr auto test_xorshift32() -> bool
{
    using etl::xorshift32;

    CHECK(xorshift32::min() == 0);
    CHECK(xorshift32::max() == etl::uint32_t(-2));
    CHECK(xorshift32::default_seed == 5489U);
    CHECK(xorshift32() == xorshift32());
    CHECK(xorshift32() != xorshift32(1));

    return true;
}

constexpr auto test_xorshift64() -> bool
{
#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    using etl::xorshift64;

    CHECK(xorshift64::min() == 0);
    CHECK(xorshift64::max() == etl::uint64_t(-2));
    CHECK(xorshift64::default_seed == 5489U);
    CHECK(xorshift64() == xorshift64());
    CHECK(xorshift64() != xorshift64(1));

#endif
    return true;
}

constexpr auto test() -> bool
{
    CHECK(test_xorshift32());
    CHECK(test_xorshift64());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
