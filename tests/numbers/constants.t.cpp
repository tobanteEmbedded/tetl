// SPDX-License-Identifier: BSL-1.0

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_APPROX(etl::numbers::e_v<T>, T(2.7182818));
    CHECK_APPROX(etl::numbers::log2e_v<T>, T(1.44269504));
    CHECK_APPROX(etl::numbers::log10e_v<T>, T(0.4342944));
    CHECK_APPROX(etl::numbers::pi_v<T>, T(3.1415926));
    CHECK_APPROX(etl::numbers::inv_sqrtpi_v<T>, T(0.5641895));
    CHECK_APPROX(etl::numbers::inv_pi_v<T>, T(0.3183098));
    CHECK_APPROX(etl::numbers::ln2_v<T>, T(0.6931471));
    CHECK_APPROX(etl::numbers::ln10_v<T>, T(2.3025850));
    CHECK_APPROX(etl::numbers::sqrt2_v<T>, T(1.4142135));
    CHECK_APPROX(etl::numbers::sqrt3_v<T>, T(1.7320508));
    CHECK_APPROX(etl::numbers::inv_sqrt3_v<T>, T(0.5773502));
    CHECK_APPROX(etl::numbers::egamma_v<T>, T(0.5772156));
    CHECK_APPROX(etl::numbers::phi_v<T>, T(1.6180339));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
