// SPDX-License-Identifier: BSL-1.0

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/numbers.hpp"

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::atan(short {0}) == 0.0);
    assert(etl::atanl(0) == 0.0L);
    assert(etl::atan(T(0)) == T(0));

    assert(approx(etl::atan(T(0.5)), T(0.463648)));
    assert(approx(etl::atan(T(1)), T(0.785398)));
    assert(approx(etl::atan(T(2)), T(1.10715)));
    assert(approx(etl::atan(T(4)), T(1.32582)));
    assert(approx(etl::atan(T(8)), T(1.44644)));
    assert(approx(etl::atan(T(16)), T(1.50838)));
    assert(approx(etl::atan(T(32)), T(1.53956)));
    assert(approx(etl::atan(T(64)), T(1.55517)));
    assert(approx(etl::atan(T(128)), T(1.56298)));
    assert(approx(etl::atan(T(1024)), T(1.56982)));

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
