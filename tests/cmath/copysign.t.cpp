// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::copysign(T(0), T(1)), T(0));
    CHECK_APPROX(etl::copysign(T(1), T(1)), T(1));
    CHECK_APPROX(etl::copysign(T(1), T(-1)), T(-1));

    CHECK_APPROX(etl::detail::copysign_fallback(T(0), T(1)), T(0));
    CHECK_APPROX(etl::detail::copysign_fallback(T(1), T(1)), T(1));
    CHECK_APPROX(etl::detail::copysign_fallback(T(1), T(-1)), T(-1));
    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return 0;
}
