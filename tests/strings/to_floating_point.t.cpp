// SPDX-License-Identifier: BSL-1.0

#include <etl/strings.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK_APPROX(etl::strings::to_floating_point<T>("0"), T(0.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("10"), T(10.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("100.0"), T(100.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("1000.000"), T(1000.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("10000"), T(10000.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("999999.0"), T(999999.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("9999999"), T(9999999.0));
    CHECK_APPROX(etl::strings::to_floating_point<T>("   9999999"), T(9999999.0));
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
