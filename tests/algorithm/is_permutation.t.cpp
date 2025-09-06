// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/iterator.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // different size
    {
        auto const a = etl::array{T(1), T(2), T(3)};
        auto const b = etl::array{T(3), T(2)};
        CHECK_FALSE(etl::is_permutation(a.begin(), a.end(), b.begin(), b.end()));
    }

    // different data
    {
        auto const a = etl::array{T(1), T(2), T(3)};
        auto const b = etl::array{T(4), T(5), T(6)};
        CHECK_FALSE(etl::is_permutation(a.begin(), a.end(), b.begin(), b.end()));
        CHECK_FALSE(etl::is_permutation(FwdIter(a.begin()), FwdIter(a.end()), b.begin(), b.end()));
        CHECK_FALSE(etl::is_permutation(FwdIter(b.begin()), FwdIter(b.end()), a.begin(), a.end()));
    }

    // same data
    {
        auto const a = etl::array{T(1), T(2), T(3)};
        auto const b = etl::array{T(1), T(2), T(3)};
        CHECK(etl::is_permutation(a.begin(), a.end(), b.begin(), b.end()));
        CHECK(etl::is_permutation(FwdIter(a.begin()), FwdIter(a.end()), b.begin(), b.end()));
    }

    // reverse data
    {
        auto const a = etl::array{T(1), T(2), T(3)};
        auto const b = etl::array{T(3), T(2), T(1)};
        CHECK(etl::is_permutation(FwdIter(a.begin()), FwdIter(a.end()), b.begin(), b.end()));
    }

    // cppreference.com example
    {
        auto const a = etl::array{T(1), T(2), T(3), T(4), T(5)};
        auto const b = etl::array{T(3), T(5), T(4), T(1), T(2)};
        auto const c = etl::array{T(3), T(5), T(4), T(1), T(1)};
        CHECK(etl::is_permutation(a.begin(), a.end(), b.begin(), b.end()));
        CHECK_FALSE(etl::is_permutation(a.begin(), a.end(), c.begin(), c.end()));
    }

    // shuffled
    {
        auto const a = etl::array{T(1), T(3), T(5), T(7), T(8), T(6), T(4), T(2)};
        auto const b = etl::array{T(2), T(3), T(5), T(8), T(7), T(6), T(4), T(1)};
        auto const c = etl::array{T(3), T(5), T(4), T(1), T(1), T(1), T(1), T(1)};
        CHECK(etl::is_permutation(a.begin(), a.end(), b.begin(), b.end()));
        CHECK_FALSE(etl::is_permutation(a.begin(), a.end(), c.begin(), c.end()));
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
