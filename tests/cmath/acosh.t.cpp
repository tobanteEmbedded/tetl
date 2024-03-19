// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    ASSERT(etl::acosh(short{1}) == 0.0);
    ASSERT(etl::acoshl(1) == 0.0L);
    ASSERT(etl::acosh(T(1)) == T(0));

    ASSERT_APPROX(etl::acosh(T(2)), T(1.31696));
    ASSERT_APPROX(etl::acosh(T(3)), T(1.76275));

    // TODO: Fix for long double
    if constexpr (!etl::is_same_v<T, long double>) {
        ASSERT(etl::isnan(etl::acosh(T(0))));
        ASSERT(etl::isnan(etl::acosh(T(0.5))));
    }

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
