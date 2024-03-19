// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/limits.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test(auto add) -> bool
{
    using limits = etl::numeric_limits<T>;

    CHECK(add(T(0), T(0)) == T(0));
    CHECK(add(T(1), T(0)) == T(1));
    CHECK(add(T(1), T(1)) == T(2));

    CHECK(add(limits::max(), T(0)) == limits::max());
    CHECK(add(limits::max(), T(1)) == limits::max());
    CHECK(add(limits::max(), T(2)) == limits::max());

    if constexpr (etl::is_signed_v<T>) {
        CHECK(add(limits::min(), T(-0)) == limits::min());
        CHECK(add(limits::min(), T(-1)) == limits::min());
        CHECK(add(limits::min(), T(-2)) == limits::min());
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<unsigned char>([](auto x, auto y) { return etl::add_sat(x, y); }));
    CHECK(test<unsigned short>([](auto x, auto y) { return etl::add_sat(x, y); }));
    CHECK(test<unsigned int>([](auto x, auto y) { return etl::add_sat(x, y); }));
    CHECK(test<unsigned long>([](auto x, auto y) { return etl::add_sat(x, y); }));

    CHECK(test<signed char>([](auto x, auto y) { return etl::add_sat(x, y); }));
    CHECK(test<signed short>([](auto x, auto y) { return etl::add_sat(x, y); }));
    CHECK(test<signed int>([](auto x, auto y) { return etl::add_sat(x, y); }));
    CHECK(test<signed long>([](auto x, auto y) { return etl::add_sat(x, y); }));

    CHECK(test<unsigned char>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    CHECK(test<unsigned short>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    CHECK(test<unsigned int>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    CHECK(test<unsigned long>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));

    CHECK(test<signed char>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    CHECK(test<signed short>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    CHECK(test<signed int>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));
    CHECK(test<signed long>([](auto x, auto y) { return etl::detail::add_sat_fallback(x, y); }));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
