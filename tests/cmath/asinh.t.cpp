// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::asinh(short{0}) == 0.0);
    CHECK(etl::asinhl(0) == 0.0L);
    CHECK(etl::asinh(T(0)) == T(0));

    CHECK_APPROX(etl::asinh(T(0.5)), T(0.481212));
    CHECK_APPROX(etl::asinh(T(1)), T(0.881374));
    CHECK_APPROX(etl::asinh(T(2)), T(1.44364));
    CHECK_APPROX(etl::asinh(T(3)), T(1.81845));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return 0;
}
