// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/limits.hpp>
    #include <etl/numeric.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_NOEXCEPT(etl::div_sat<T>(T(0), T(1)));
    CHECK_NOEXCEPT(etl::div_sat<T>(T(1), T(1)));

    CHECK(etl::div_sat(T(0), T(1)) == T(0));
    CHECK(etl::div_sat(T(2), T(1)) == T(2));

    if constexpr (etl::is_signed_v<T>) {
        using limits = etl::numeric_limits<T>;
        CHECK(etl::div_sat(T(2), T(-1)) == T(-2));
        CHECK(etl::div_sat(limits::min(), T(-1)) == limits::max());
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
