// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include <etl/concepts.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <etl::floating_point Float>
constexpr auto test() -> bool
{
    auto const nan = static_cast<Float>(etl::nan(""));

    // hypot(x, y)
    assert(etl::isnan(etl::hypot(nan, Float(1))));
    assert(etl::isnan(etl::hypot(Float(42), nan)));

    assert(approx(etl::hypot(Float(0), Float(1)), Float(1)));
    assert(approx(etl::hypot(Float(1), Float(1)), Float(1.414214)));

    // hypot(x, y, z)
    assert(etl::isnan(etl::hypot(nan, Float(1), Float(1))));
    assert(etl::isnan(etl::hypot(Float(42), Float(42), nan)));
    assert(approx(etl::hypot(Float(0), Float(0), Float(1)), Float(1)));
    assert(approx(etl::hypot(Float(1), Float(1), Float(1)), Float(1.732051)));

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
