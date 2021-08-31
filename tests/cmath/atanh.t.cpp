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
    assert(etl::atanh(short { 0 }) == 0.0);
    assert(etl::atanhl(0) == 0.0L);
    assert(etl::atanh(T(0)) == T(0));

    assert(approx(etl::atanh(T(0.5)), T(0.549306)));

    assert(etl::isinf(etl::atanh(T(1))));
    assert(etl::isnan(etl::atanh(T(2))));

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