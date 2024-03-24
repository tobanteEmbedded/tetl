// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // equal_to
    {
        auto data = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        etl::unique(data.begin(), data.end());
        CHECK(data[0] == T(1));
        CHECK(data[1] == T(2));
        CHECK(data[2] == T(3));
    }

    // not_equal_to
    {
        auto data = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        etl::unique(data.begin(), data.end(), etl::not_equal_to{});
        CHECK(data[0] == T(1));
        CHECK(data[1] == T(1));
        CHECK(data[2] == T(1));
    }

    // equal_to
    {
        auto src = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        decltype(src) dest{};

        etl::unique_copy(src.begin(), src.end(), begin(dest));
        CHECK(dest[0] == T(1));
        CHECK(dest[1] == T(2));
        CHECK(dest[2] == T(3));
    }

    // not_equal_to
    {
        auto src = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        decltype(src) dest{};

        auto cmp = etl::not_equal_to{};
        etl::unique_copy(src.begin(), src.end(), begin(dest), cmp);
        CHECK(dest[0] == T(1));
        CHECK(dest[1] == T(1));
        CHECK(dest[2] == T(1));
    }
    return true;
}

constexpr auto test_all() -> bool
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
