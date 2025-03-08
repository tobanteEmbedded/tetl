// SPDX-License-Identifier: BSL-1.0
#include <etl/cstdlib.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename T, typename F>
static constexpr auto test(F func) -> bool
{
    auto check = [&](auto const* str, auto expected) -> bool {
        char const* end = nullptr;
        CHECK_APPROX(func(str, &end), expected);
        CHECK(end != str);
        return true;
    };

    CHECK(check("0", T(0)));
    CHECK(check("10", T(10)));
    CHECK(check("100.0", T(100)));
    CHECK(check("143.0", T(143)));
    CHECK(check("1000.000", T(1000)));
    CHECK(check("10000", T(10000)));
    CHECK(check("999999.0", T(999999)));
    CHECK(check("9999999", T(9999999)));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<float>(etl::strtof));
    CHECK(test<double>(etl::strtod));
    CHECK(test<long double>(etl::strtold));
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
