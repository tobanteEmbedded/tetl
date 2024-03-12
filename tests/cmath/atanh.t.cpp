// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/numbers.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::atanh(short{0}) == 0.0);
    assert(etl::atanhl(0) == 0.0L);
    assert(etl::atanh(T(0)) == T(0));

    assert(approx(etl::atanh(T(0.5)), T(0.549306)));

    // TODO: Fix long double tests
    if constexpr (!etl::is_same_v<T, long double>) {
        assert(etl::isinf(etl::atanh(T(1))));
        assert(etl::isnan(etl::atanh(T(2))));
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
