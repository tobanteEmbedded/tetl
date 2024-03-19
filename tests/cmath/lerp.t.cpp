// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

namespace {
template <typename Float>
constexpr auto test() -> bool
{
    ASSERT_NOEXCEPT(etl::lerp(Float(0), Float(1), Float(0)));
    ASSERT_SAME_TYPE(decltype(etl::lerp(Float(0), Float(1), Float(0))), Float);

    ASSERT_APPROX(etl::lerp(Float(0), Float(1), Float(0)), Float(0), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(1), Float(0.5)), Float(0.5), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(1), Float(1)), Float(1), Float(1e-6));

    ASSERT_APPROX(etl::lerp(Float(0), Float(20), Float(0)), Float(0), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(20), Float(0.5)), Float(10), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(20), Float(1)), Float(20), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(20), Float(2)), Float(40), Float(1e-6));

    ASSERT_APPROX(etl::lerp(Float(20), Float(0), Float(0)), Float(20), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(20), Float(0), Float(0.5)), Float(10), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(20), Float(0), Float(1)), Float(0), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(20), Float(0), Float(2)), Float(-20), Float(1e-6));

    ASSERT_APPROX(etl::lerp(Float(0), Float(-20), Float(0)), Float(0), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(-20), Float(0.5)), Float(-10), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(-20), Float(1)), Float(-20), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(0), Float(-20), Float(2)), Float(-40), Float(1e-6));

    ASSERT_APPROX(etl::lerp(Float(-10), Float(-20), Float(0)), Float(-10), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(-10), Float(-20), Float(0.5)), Float(-15), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(-10), Float(-20), Float(1)), Float(-20), Float(1e-6));
    ASSERT_APPROX(etl::lerp(Float(-10), Float(-20), Float(2)), Float(-30), Float(1e-6));
    return true;
}
} // namespace

auto main() -> int
{
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    return 0;
}
