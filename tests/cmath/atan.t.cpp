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
    assert(etl::atan(short { 0 }) == 0.0);
    assert(etl::atanl(0) == 0.0L);
    assert(etl::atan(T(0)) == T(0));

    assert(approx(etl::atan(T(0.5)), T(0.463648)));
    assert(approx(etl::atan(T(1)), T(0.785398)));
    assert(approx(etl::atan(T(2)), T(1.10715)));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    assert(test<float>());

    static_assert(test<double>());
    assert(test<double>());

    return 0;
}