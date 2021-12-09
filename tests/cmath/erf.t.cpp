/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(approx(etl::erf(T(0.5)), T(0.5204998778)));
    assert(approx(etl::erf(T(1)), T(0.8427007929)));
    assert(approx(etl::erf(T(2)), T(0.995322265)));
    assert(approx(etl::erf(T(4)), T(0.9999999846)));

    // TODO: Fix for long double
    if constexpr (!etl::is_same_v<T, long double>) { assert(approx(etl::erf(T(0)), T(0))); }

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