// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto const in  = etl::static_vector<T, 1>{};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(out.first == in.end());
        ASSERT(out.second == in.end());
    }

    {
        auto const in  = etl::array{T(1)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(1));
        ASSERT(*out.second == T(1));
    }

    {
        auto const in  = etl::array{T(1), T(2)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(1));
        ASSERT(*out.second == T(2));
    }

    {
        auto const in  = etl::array{T(1), T(2), T(3)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(1));
        ASSERT(*out.second == T(3));
    }

    {
        auto const in  = etl::array{T(1), T(2), T(3)};
        auto const out = etl::minmax_element(in.begin(), in.end(), etl::greater{});
        ASSERT(*out.first == T(3));
        ASSERT(*out.second == T(1));
    }

    {
        auto const in  = etl::array{T(1), T(3), T(3)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(1));
        ASSERT(*out.second == T(3));
    }

    {
        auto const in  = etl::array{T(1), T(2), T(3), T(4), T(5), T(6)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(1));
        ASSERT(*out.second == T(6));
    }

    {
        auto const in  = etl::array{T(1), T(4), T(5), T(3), T(2)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(1));
        ASSERT(*out.second == T(5));
    }

    {
        auto const in  = etl::array{T(100), T(99), T(0)};
        auto const out = etl::minmax_element(in.begin(), in.end());
        ASSERT(*out.first == T(0));
        ASSERT(*out.second == T(100));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<char>());
    ASSERT(test<char8_t>());
    ASSERT(test<char16_t>());
    ASSERT(test<char32_t>());
    ASSERT(test<wchar_t>());

    ASSERT(test<etl::int8_t>());
    ASSERT(test<etl::int16_t>());
    ASSERT(test<etl::int32_t>());
    ASSERT(test<etl::int64_t>());
    ASSERT(test<etl::uint8_t>());
    ASSERT(test<etl::uint16_t>());
    ASSERT(test<etl::uint32_t>());
    ASSERT(test<etl::uint64_t>());
    ASSERT(test<etl::size_t>());
    ASSERT(test<etl::ptrdiff_t>());

    ASSERT(test<float>());
    ASSERT(test<double>());

    return true;
}

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
