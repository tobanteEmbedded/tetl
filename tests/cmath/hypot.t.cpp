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
    CHECK_NOEXCEPT(etl::hypot(Float(1), Float(2)));
    CHECK_SAME_TYPE(decltype(etl::hypot(Float(1), Float(2))), Float);

    CHECK(etl::isnan(etl::hypot(nan, Float(1))));
    CHECK(etl::isnan(etl::hypot(Float(42), nan)));

    CHECK(etl::isinf(etl::hypot(inf, Float(1))));
    CHECK(etl::isinf(etl::hypot(Float(42), inf)));

    CHECK_APPROX(etl::hypot(Float(0), Float(1)), Float(1));
    CHECK_APPROX(etl::hypot(Float(1), Float(1)), Float(1.414214));

    // etl::hypotf(x, y)
    if constexpr (etl::same_as<Float, float>) {
        CHECK_NOEXCEPT(etl::hypotf(1.0F, 2.0F));
        CHECK_SAME_TYPE(decltype(etl::hypotf(1.0F, 2.0F)), float);

        CHECK(etl::isnan(etl::hypotf(nan, 1.0F)));
        CHECK(etl::isnan(etl::hypotf(42.0F, nan)));

        CHECK(etl::isinf(etl::hypotf(inf, 1.0F)));
        CHECK(etl::isinf(etl::hypotf(42.0F, inf)));

        CHECK_APPROX(etl::hypotf(0.0F, 1.0F), 1.0F);
        CHECK_APPROX(etl::hypotf(1.0F, 1.0F), 1.414214F);
    }

    // etl::hypotl(x, y)
    if constexpr (etl::same_as<Float, long double>) {
        CHECK_NOEXCEPT(etl::hypotl(1.0L, 2.0L));
        CHECK_SAME_TYPE(decltype(etl::hypotl(1.0L, 2.0L)), long double);

        CHECK(etl::isnan(etl::hypotl(nan, 1.0L)));
        CHECK(etl::isnan(etl::hypotl(42.0L, nan)));

        CHECK(etl::isinf(etl::hypotl(inf, 1.0L)));
        CHECK(etl::isinf(etl::hypotl(42.0L, inf)));

        CHECK_APPROX(etl::hypotl(0.0L, 1.0L), 1.0L);
        CHECK_APPROX(etl::hypotl(1.0L, 1.0L), 1.414214L);
    }

    // etl::hypot(x, y, z)
    CHECK_NOEXCEPT(etl::hypot(Float(1), Float(2), Float(3)));
    CHECK_SAME_TYPE(decltype(etl::hypot(Float(1), Float(2), Float(3))), Float);

    CHECK(etl::isnan(etl::hypot(nan, Float(1), Float(1))));
    CHECK(etl::isnan(etl::hypot(Float(42), nan, Float(42))));
    CHECK(etl::isnan(etl::hypot(Float(42), Float(42), nan)));

    CHECK(etl::isinf(etl::hypot(inf, Float(1), Float(1))));
    CHECK(etl::isinf(etl::hypot(Float(42), inf, Float(42))));
    CHECK(etl::isinf(etl::hypot(Float(42), Float(42), inf)));

    CHECK_APPROX(etl::hypot(Float(0), Float(0), Float(1)), Float(1));
    CHECK_APPROX(etl::hypot(Float(1), Float(1), Float(1)), Float(1.732051));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
