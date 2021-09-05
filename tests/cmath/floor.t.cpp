/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(approx(etl::floor(T(0)), T(0)));
    assert(approx(etl::floor(T(1)), T(1)));
    assert(approx(etl::floor(T(2)), T(2)));
    assert(approx(etl::floor(T(-2)), T(-2)));

    assert(approx(etl::floor(T(0.1)), T(0)));
    assert(approx(etl::floor(T(0.2)), T(0)));
    assert(approx(etl::floor(T(0.3)), T(0)));
    assert(approx(etl::floor(T(0.4)), T(0)));
    assert(approx(etl::floor(T(0.5)), T(0)));
    assert(approx(etl::floor(T(0.6)), T(0)));
    assert(approx(etl::floor(T(0.7)), T(0)));
    assert(approx(etl::floor(T(0.8)), T(0)));
    assert(approx(etl::floor(T(0.9)), T(0)));
    assert(approx(etl::floor(T(0.99)), T(0)));
    assert(approx(etl::floor(T(1.01)), T(1)));

    assert(approx(etl::floor(T(-0.1)), T(-1)));
    assert(approx(etl::floor(T(-0.2)), T(-1)));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());

    assert(test<float>());
    assert(test<double>());

    return 0;
}