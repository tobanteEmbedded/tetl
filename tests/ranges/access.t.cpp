// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/concepts.hpp>
    #include <etl/iterator.hpp>
    #include <etl/memory.hpp>
    #include <etl/ranges.hpp>
    #include <etl/string_view.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::ranges::range<etl::string_view>);
    CHECK(etl::ranges::sized_range<etl::string_view>);
    CHECK_SAME_TYPE(etl::ranges::range_size_t<etl::string_view>, etl::size_t);
    CHECK_SAME_TYPE(etl::ranges::range_difference_t<etl::string_view>, etl::ptrdiff_t);
    CHECK_SAME_TYPE(etl::ranges::range_value_t<etl::string_view>, char);
    CHECK_SAME_TYPE(etl::ranges::range_reference_t<etl::string_view>, char const&);
    CHECK_SAME_TYPE(etl::ranges::sentinel_t<etl::string_view>, etl::ranges::iterator_t<etl::string_view>);

    {
        T data[2]{T(1), T(2)};
        CHECK(etl::ranges::range<decltype(data)>);
        CHECK(etl::ranges::sized_range<decltype(data)>);
        CHECK_SAME_TYPE(etl::ranges::range_size_t<decltype(data)>, etl::size_t);
        CHECK_SAME_TYPE(etl::ranges::range_difference_t<decltype(data)>, etl::ptrdiff_t);
        CHECK_SAME_TYPE(etl::ranges::range_value_t<decltype(data)>, T);
        CHECK_SAME_TYPE(etl::ranges::range_reference_t<decltype(data)>, T&);
        CHECK_SAME_TYPE(etl::ranges::sentinel_t<decltype(data)>, etl::ranges::iterator_t<decltype(data)>);
        CHECK(etl::ranges::size(data) == 2);
        CHECK(etl::ranges::begin(data) == etl::addressof(data[0]));
        CHECK(etl::ranges::end(data) == etl::next(etl::addressof(data[0]), 2));
    }

    {
        auto data = etl::to_array<T>({1, 2, 3});
        CHECK(etl::ranges::range<decltype(data)>);
        CHECK(etl::ranges::sized_range<decltype(data)>);
        CHECK_SAME_TYPE(etl::ranges::range_size_t<decltype(data)>, etl::size_t);
        CHECK_SAME_TYPE(etl::ranges::range_difference_t<decltype(data)>, etl::ptrdiff_t);
        CHECK_SAME_TYPE(etl::ranges::range_value_t<decltype(data)>, T);
        CHECK_SAME_TYPE(etl::ranges::range_reference_t<decltype(data)>, T&);
        CHECK_SAME_TYPE(etl::ranges::sentinel_t<decltype(data)>, etl::ranges::iterator_t<decltype(data)>);
        CHECK(etl::ranges::size(data) == 3);
        CHECK(etl::ranges::begin(data) == data.begin());
        CHECK(etl::ranges::end(data) == data.end());
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
