// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::atan(short{0}) == 0.0);
    CHECK(etl::atanl(0) == 0.0L);
    CHECK(etl::atan(T(0)) == T(0));

    CHECK_APPROX(etl::atan(T(0.5)), T(0.463648));
    CHECK_APPROX(etl::atan(T(1)), T(0.785398));
    CHECK_APPROX(etl::atan(T(2)), T(1.10715));
    CHECK_APPROX(etl::atan(T(4)), T(1.32582));
    CHECK_APPROX(etl::atan(T(8)), T(1.44644));
    CHECK_APPROX(etl::atan(T(16)), T(1.50838));
    CHECK_APPROX(etl::atan(T(32)), T(1.53956));
    CHECK_APPROX(etl::atan(T(64)), T(1.55517));
    CHECK_APPROX(etl::atan(T(128)), T(1.56298));
    CHECK_APPROX(etl::atan(T(1024)), T(1.56982));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
