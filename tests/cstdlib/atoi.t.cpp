// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cstdlib;
#else
    #include <etl/cstdlib.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::atoi("0") == T(0));
    CHECK(etl::atoi("10") == T(10));
    CHECK(etl::atoi("99") == T(99));
    CHECK(etl::atoi("143") == T(143));
    CHECK(etl::atoi("999") == T(999));
    CHECK(etl::atoi("1111") == T(1111));

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(etl::atoi("99999") == T(99999));
    CHECK(etl::atoi("999999") == T(999999));
    CHECK(etl::atoi("123456789") == T(123456789));
#endif

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<int>());
    CHECK(test<long>());
    CHECK(test<long long>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
