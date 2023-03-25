/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/random.hpp"

#include "testing/testing.hpp"

constexpr auto test_xorshift32() -> bool
{
    using etl::xorshift32;

    assert(xorshift32::min() == 0);
    assert(xorshift32::max() == etl::uint32_t(-2));
    assert(xorshift32::default_seed == 5489U);
    assert(xorshift32() == xorshift32());
    assert(xorshift32() != xorshift32(1));

    return true;
}

constexpr auto test_xorshift64() -> bool
{
#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    using etl::xorshift64;

    assert(xorshift64::min() == 0);
    assert(xorshift64::max() == etl::uint64_t(-2));
    assert(xorshift64::default_seed == 5489U);
    assert(xorshift64() == xorshift64());
    assert(xorshift64() != xorshift64(1));

#endif
    return true;
}

constexpr auto test() -> bool
{
    assert(test_xorshift32());
    assert(test_xorshift64());
    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
