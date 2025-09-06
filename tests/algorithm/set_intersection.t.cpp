// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/iterator.hpp>
    #include <etl/vector.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // cppreference.com example
    {
        etl::array<T, 8> v1{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        etl::array<T, 4> v2{T(5), T(7), T(9), T(10)};
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 2> intersection{};
        etl::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), etl::back_inserter(intersection));

        CHECK(intersection[0] == T{5});
        CHECK(intersection[1] == T{7});
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
