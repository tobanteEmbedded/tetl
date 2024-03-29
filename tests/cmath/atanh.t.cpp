// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::atanh(short{0}) == 0.0);
    CHECK(etl::atanhl(0) == 0.0L);
    CHECK(etl::atanh(T(0)) == T(0));

    CHECK_APPROX(etl::atanh(T(0.5)), T(0.549306));

    // TODO: Fix long double tests
    if constexpr (!etl::is_same_v<T, long double>) {
        CHECK(etl::isinf(etl::atanh(T(1))));
        CHECK(etl::isnan(etl::atanh(T(2))));
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
