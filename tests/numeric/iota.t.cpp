// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/numeric.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // from 0
    {
        auto data = etl::array<T, 4>{};
        etl::iota(data.begin(), data.end(), T{0});
        CHECK(data[0] == 0);
        CHECK(data[1] == 1);
        CHECK(data[2] == 2);
        CHECK(data[3] == 3);
    }

    // from 42
    {
        auto data = etl::array<T, 4>{};
        etl::iota(data.begin(), data.end(), T{42});
        CHECK(data[0] == 42);
        CHECK(data[1] == 43);
        CHECK(data[2] == 44);
        CHECK(data[3] == 45);
    }
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

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
