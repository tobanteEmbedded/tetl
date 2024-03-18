// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/limits.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test(auto add) -> bool
{
    using limits = etl::numeric_limits<T>;

    ASSERT(add(T(0), T(0)) == T(0));
    ASSERT(add(T(1), T(0)) == T(1));
    ASSERT(add(T(1), T(1)) == T(2));

    ASSERT(add(limits::max(), T(0)) == limits::max());
    ASSERT(add(limits::max(), T(1)) == limits::max());
    ASSERT(add(limits::max(), T(2)) == limits::max());

    if constexpr (etl::is_signed_v<T>) {
        ASSERT(add(limits::min(), T(-0)) == limits::min());
        ASSERT(add(limits::min(), T(-1)) == limits::min());
        ASSERT(add(limits::min(), T(-2)) == limits::min());
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<unsigned char>([](auto x, auto y) { return etl::add_sat(x, y); }));
    assert(test<unsigned short>([](auto x, auto y) { return etl::add_sat(x, y); }));
    assert(test<unsigned int>([](auto x, auto y) { return etl::add_sat(x, y); }));
    assert(test<unsigned long>([](auto x, auto y) { return etl::add_sat(x, y); }));

    assert(test<signed char>([](auto x, auto y) { return etl::add_sat(x, y); }));
    assert(test<signed short>([](auto x, auto y) { return etl::add_sat(x, y); }));
    assert(test<signed int>([](auto x, auto y) { return etl::add_sat(x, y); }));
    assert(test<signed long>([](auto x, auto y) { return etl::add_sat(x, y); }));

    assert(test<unsigned char>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    assert(test<unsigned short>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    assert(test<unsigned int>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    assert(test<unsigned long>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));

    assert(test<signed char>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    assert(test<signed short>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    assert(test<signed int>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    assert(test<signed long>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
