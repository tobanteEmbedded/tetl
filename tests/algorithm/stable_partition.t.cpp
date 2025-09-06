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
    constexpr auto pred = [](auto n) { return n < T(10); };

    // empty
    {
        auto vec = etl::static_vector<T, 1>{};
        CHECK(etl::stable_partition(begin(vec), end(vec), pred) == vec.begin());
    }

    // single false
    {
        auto vec = etl::static_vector<T, 1>(etl::c_array<T, 1>{T(10)});
        CHECK(etl::stable_partition(begin(vec), end(vec), pred) == vec.begin());
    }

    // single true
    {
        auto vec = etl::static_vector<T, 1>(etl::c_array<T, 1>{T(9)});
        CHECK(etl::stable_partition(begin(vec), end(vec), pred) == etl::next(vec.begin()));
    }

    // range
    {
        auto arr = etl::array{T(11), T(1), T(12), T(13), T(2), T(3), T(4)};
        etl::stable_partition(begin(arr), end(arr), pred);
        CHECK(arr == etl::array{T(1), T(2), T(3), T(4), T(11), T(12), T(13)});
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
