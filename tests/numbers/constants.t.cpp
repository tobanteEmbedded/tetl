// SPDX-License-Identifier: BSL-1.0

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_APPROX(etl::numbers::e_v<T>, T(2.7182818));
    ASSERT_APPROX(etl::numbers::log2e_v<T>, T(1.44269504));
    ASSERT_APPROX(etl::numbers::log10e_v<T>, T(0.4342944));
    ASSERT_APPROX(etl::numbers::pi_v<T>, T(3.1415926));
    ASSERT_APPROX(etl::numbers::inv_sqrtpi_v<T>, T(0.5641895));
    ASSERT_APPROX(etl::numbers::inv_pi_v<T>, T(0.3183098));
    ASSERT_APPROX(etl::numbers::ln2_v<T>, T(0.6931471));
    ASSERT_APPROX(etl::numbers::ln10_v<T>, T(2.3025850));
    ASSERT_APPROX(etl::numbers::sqrt2_v<T>, T(1.4142135));
    ASSERT_APPROX(etl::numbers::sqrt3_v<T>, T(1.7320508));
    ASSERT_APPROX(etl::numbers::inv_sqrt3_v<T>, T(0.5773502));
    ASSERT_APPROX(etl::numbers::egamma_v<T>, T(0.5772156));
    ASSERT_APPROX(etl::numbers::phi_v<T>, T(1.6180339));

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    return true;
}

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
