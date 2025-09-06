// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/limits.hpp>
    #include <etl/numeric.hpp>
    #include <etl/utility.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    using limits_int = etl::numeric_limits<int>;
    using limits_val = etl::numeric_limits<T>;

    CHECK_NOEXCEPT(etl::saturate_cast<T>(T(0)));
    CHECK_NOEXCEPT(etl::saturate_cast<T>(T(1)));

    CHECK(etl::saturate_cast<T>(T(0)) == T(0));
    CHECK(etl::saturate_cast<T>(0) == T(0));
    CHECK(etl::saturate_cast<T>(0LL) == T(0));

    if constexpr (etl::cmp_less(limits_int::min(), limits_val::min())) {
        CHECK(etl::saturate_cast<T>(limits_int::min()) == limits_val::min());
    } else {
        CHECK(etl::saturate_cast<T>(limits_int::min()) == limits_int::min());
    }

    if constexpr (etl::cmp_greater(limits_int::max(), limits_val::max())) {
        CHECK(etl::saturate_cast<T>(limits_int::max()) == limits_val::max());
    } else {
        CHECK(etl::saturate_cast<T>(limits_int::max()) == limits_int::max());
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
