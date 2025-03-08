// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_APPROX(etl::tan(T(0)), T(0));
    CHECK_APPROX(etl::tan(T(etl::numbers::pi)), T(0));
    CHECK_APPROX(etl::tanf(0.0F), 0.0F);
    CHECK_APPROX(etl::tanl(0.0L), 0.0L);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
