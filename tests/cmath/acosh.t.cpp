// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::acosh(short{1}) == 0.0);
    assert(etl::acoshl(1) == 0.0L);
    assert(etl::acosh(T(1)) == T(0));

    assert(approx(etl::acosh(T(2)), T(1.31696)));
    assert(approx(etl::acosh(T(3)), T(1.76275)));

    // TODO: Fix for long double
    if constexpr (!etl::is_same_v<T, long double>) {
        assert(etl::isnan(etl::acosh(T(0))));
        assert(etl::isnan(etl::acosh(T(0.5))));
    }

    return true;
}

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());
    return 0;
}
