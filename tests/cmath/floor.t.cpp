// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_APPROX(etl::floor(T(0)), T(0));
    ASSERT_APPROX(etl::floor(T(1)), T(1));
    ASSERT_APPROX(etl::floor(T(2)), T(2));
    ASSERT_APPROX(etl::floor(T(-2)), T(-2));

    ASSERT_APPROX(etl::floor(T(0.1)), T(0));
    ASSERT_APPROX(etl::floor(T(0.2)), T(0));
    ASSERT_APPROX(etl::floor(T(0.3)), T(0));
    ASSERT_APPROX(etl::floor(T(0.4)), T(0));
    ASSERT_APPROX(etl::floor(T(0.5)), T(0));
    ASSERT_APPROX(etl::floor(T(0.6)), T(0));
    ASSERT_APPROX(etl::floor(T(0.7)), T(0));
    ASSERT_APPROX(etl::floor(T(0.8)), T(0));
    ASSERT_APPROX(etl::floor(T(0.9)), T(0));
    ASSERT_APPROX(etl::floor(T(0.99)), T(0));
    ASSERT_APPROX(etl::floor(T(1.01)), T(1));

    ASSERT_APPROX(etl::floor(T(-0.1)), T(-1));
    ASSERT_APPROX(etl::floor(T(-0.2)), T(-1));

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    return 0;
}
