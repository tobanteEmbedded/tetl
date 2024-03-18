// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/limits.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using limits = etl::numeric_limits<T>;

    ASSERT(etl::add_sat(T(0), T(0)) == T(0));
    ASSERT(etl::add_sat(T(1), T(0)) == T(1));
    ASSERT(etl::add_sat(T(1), T(1)) == T(2));

    ASSERT(etl::add_sat(limits::max(), T(0)) == limits::max());
    ASSERT(etl::add_sat(limits::max(), T(1)) == limits::max());
    ASSERT(etl::add_sat(limits::max(), T(2)) == limits::max());

    if constexpr (etl::is_signed_v<T>) {
        ASSERT(etl::add_sat(limits::min(), T(-0)) == limits::min());
        ASSERT(etl::add_sat(limits::min(), T(-1)) == limits::min());
        ASSERT(etl::add_sat(limits::min(), T(-2)) == limits::min());
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<unsigned char>());
    assert(test<unsigned short>());
    assert(test<unsigned int>());
    // assert(test<unsigned long>());

    assert(test<signed char>());
    assert(test<signed short>());
    assert(test<signed int>());
    // assert(test<signed long>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
