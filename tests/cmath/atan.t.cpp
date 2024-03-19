// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT(etl::atan(short{0}) == 0.0);
    ASSERT(etl::atanl(0) == 0.0L);
    ASSERT(etl::atan(T(0)) == T(0));

    ASSERT_APPROX(etl::atan(T(0.5)), T(0.463648));
    ASSERT_APPROX(etl::atan(T(1)), T(0.785398));
    ASSERT_APPROX(etl::atan(T(2)), T(1.10715));
    ASSERT_APPROX(etl::atan(T(4)), T(1.32582));
    ASSERT_APPROX(etl::atan(T(8)), T(1.44644));
    ASSERT_APPROX(etl::atan(T(16)), T(1.50838));
    ASSERT_APPROX(etl::atan(T(32)), T(1.53956));
    ASSERT_APPROX(etl::atan(T(64)), T(1.55517));
    ASSERT_APPROX(etl::atan(T(128)), T(1.56298));
    ASSERT_APPROX(etl::atan(T(1024)), T(1.56982));

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
