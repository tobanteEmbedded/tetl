/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::lerp(T(0), T(1), T(0)) == T(0));
    assert(etl::lerp(T(0), T(1), T(0.5)) == T(0.5));

    assert(etl::lerp(T(0), T(20), T(0)) == T(0));
    assert(etl::lerp(T(0), T(20), T(0.5)) == T(10));
    assert(etl::lerp(T(0), T(20), T(2)) == T(40));

    assert(etl::lerp(T(20), T(0), T(0)) == T(20));
    assert(etl::lerp(T(20), T(0), T(0.5)) == T(10));
    assert(etl::lerp(T(20), T(0), T(2)) == T(-20));

    assert(etl::lerp(T(0), T(-20), T(0)) == T(0));
    assert(etl::lerp(T(0), T(-20), T(0.5)) == T(-10));
    assert(etl::lerp(T(0), T(-20), T(2)) == T(-40));

    assert(etl::lerp(T(-10), T(-20), T(0)) == T(-10));
    assert(etl::lerp(T(-10), T(-20), T(0.5)) == T(-15));
    assert(etl::lerp(T(-10), T(-20), T(2)) == T(-30));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    assert(test<float>());

    static_assert(test<double>());
    assert(test<double>());

    static_assert(test<long double>());
    assert(test<long double>());
    return 0;
}