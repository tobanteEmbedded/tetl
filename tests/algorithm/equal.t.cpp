// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/functional.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    auto lhs = etl::array<T, 2>{T{0}, T{1}};
    auto rhs = etl::array<T, 2>{T{0}, T{1}};
    auto cmp = etl::not_equal_to{};

    CHECK(etl::equal(lhs.begin(), lhs.end(), rhs.begin()));
    CHECK(etl::equal(InIter(lhs.begin()), InIter(lhs.end()), InIter(rhs.begin())));
    CHECK(etl::equal(FwdIter(lhs.begin()), FwdIter(lhs.end()), FwdIter(rhs.begin())));

    CHECK_FALSE(etl::equal(lhs.begin(), lhs.end(), rhs.begin(), cmp));
    CHECK_FALSE(etl::equal(InIter(lhs.begin()), InIter(lhs.end()), InIter(rhs.begin()), cmp));

    CHECK(etl::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end()));
    CHECK_FALSE(etl::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), cmp));

    auto small = etl::array{T(1)};
    CHECK_FALSE(etl::equal(lhs.begin(), lhs.end(), small.begin(), small.end(), cmp));

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
