// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/concepts.hpp>
#include <etl/limits.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

namespace {

template <etl::floating_point Float>
constexpr auto test() -> bool
{
    auto const nan = etl::numeric_limits<Float>::quiet_NaN();
    auto const inf = etl::numeric_limits<Float>::infinity();

    // etl::hypot(x, y)
    ASSERT_NOEXCEPT(etl::hypot(Float(1), Float(2)));
    ASSERT_SAME_TYPE(decltype(etl::hypot(Float(1), Float(2))), Float);

    ASSERT(etl::isnan(etl::hypot(nan, Float(1))));
    ASSERT(etl::isnan(etl::hypot(Float(42), nan)));

    ASSERT(etl::isinf(etl::hypot(inf, Float(1))));
    ASSERT(etl::isinf(etl::hypot(Float(42), inf)));

    ASSERT_APPROX(etl::hypot(Float(0), Float(1)), Float(1));
    ASSERT_APPROX(etl::hypot(Float(1), Float(1)), Float(1.414214));

    // etl::hypotf(x, y)
    if constexpr (etl::same_as<Float, float>) {
        ASSERT_NOEXCEPT(etl::hypotf(1.0F, 2.0F));
        ASSERT_SAME_TYPE(decltype(etl::hypotf(1.0F, 2.0F)), float);

        ASSERT(etl::isnan(etl::hypotf(nan, 1.0F)));
        ASSERT(etl::isnan(etl::hypotf(42.0F, nan)));

        ASSERT(etl::isinf(etl::hypotf(inf, 1.0F)));
        ASSERT(etl::isinf(etl::hypotf(42.0F, inf)));

        ASSERT_APPROX(etl::hypotf(0.0F, 1.0F), 1.0F);
        ASSERT_APPROX(etl::hypotf(1.0F, 1.0F), 1.414214F);
    }

    // etl::hypotl(x, y)
    if constexpr (etl::same_as<Float, long double>) {
        ASSERT_NOEXCEPT(etl::hypotl(1.0L, 2.0L));
        ASSERT_SAME_TYPE(decltype(etl::hypotl(1.0L, 2.0L)), long double);

        ASSERT(etl::isnan(etl::hypotl(nan, 1.0L)));
        ASSERT(etl::isnan(etl::hypotl(42.0L, nan)));

        ASSERT(etl::isinf(etl::hypotl(inf, 1.0L)));
        ASSERT(etl::isinf(etl::hypotl(42.0L, inf)));

        ASSERT_APPROX(etl::hypotl(0.0L, 1.0L), 1.0L);
        ASSERT_APPROX(etl::hypotl(1.0L, 1.0L), 1.414214L);
    }

    // etl::hypot(x, y, z)
    ASSERT_NOEXCEPT(etl::hypot(Float(1), Float(2), Float(3)));
    ASSERT_SAME_TYPE(decltype(etl::hypot(Float(1), Float(2), Float(3))), Float);

    ASSERT(etl::isnan(etl::hypot(nan, Float(1), Float(1))));
    ASSERT(etl::isnan(etl::hypot(Float(42), nan, Float(42))));
    ASSERT(etl::isnan(etl::hypot(Float(42), Float(42), nan)));

    ASSERT(etl::isinf(etl::hypot(inf, Float(1), Float(1))));
    ASSERT(etl::isinf(etl::hypot(Float(42), inf, Float(42))));
    ASSERT(etl::isinf(etl::hypot(Float(42), Float(42), inf)));

    ASSERT_APPROX(etl::hypot(Float(0), Float(0), Float(1)), Float(1));
    ASSERT_APPROX(etl::hypot(Float(1), Float(1), Float(1)), Float(1.732051));

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
