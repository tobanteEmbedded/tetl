/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::abs(T(0)) == T(0));

    assert(etl::abs(T(1)) == T(1));
    assert(etl::abs(T(2)) == T(2));
    assert(etl::abs(T(3)) == T(3));

    assert(etl::abs(T(-1)) == T(1));
    assert(etl::abs(T(-2)) == T(2));
    assert(etl::abs(T(-3)) == T(3));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());
    return 0;
}