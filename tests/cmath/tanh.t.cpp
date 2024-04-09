// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::tanh(T(0)), T(0));
    CHECK_APPROX(etl::tanh(T(1)), T(0.76159415595));

    CHECK_APPROX(etl::tanhf(0.0F), 0.0F);
    CHECK_APPROX(etl::tanhf(1.0F), 0.76159415595F);

    CHECK_APPROX(etl::tanhl(0.0L), 0.0L);
    CHECK_APPROX(etl::tanhl(1.0L), 0.76159415595L);

    CHECK_APPROX(etl::tanh(0U), 0.0);
    CHECK_APPROX(etl::tanh(0L), 0.0);
    CHECK_APPROX(etl::tanh(1U), 0.76159415595);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
