/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::asinh(short { 0 }) == 0.0);
    assert(etl::asinhl(0) == 0.0L);
    assert(etl::asinh(T(0)) == T(0));

    assert(approx(etl::asinh(T(0.5)), T(0.481212)));
    assert(approx(etl::asinh(T(1)), T(0.881374)));
    assert(approx(etl::asinh(T(2)), T(1.44364)));
    assert(approx(etl::asinh(T(3)), T(1.81845)));

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