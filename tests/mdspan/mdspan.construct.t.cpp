// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/array.hpp>

#include "testing/testing.hpp"

template <typename T, typename Index>
[[nodiscard]] constexpr auto test() -> bool
{
    // 1. 1D-Dynamic
    {
        auto m = etl::mdspan<T, etl::dextents<Index, 1>>{};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 0);
    }

    // 1. 2D-Dynamic
    {
        auto m = etl::mdspan<T, etl::dextents<Index, 2>>{};
        CHECK(m.rank() == 2);
        CHECK(m.rank_dynamic() == 2);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 0);
        CHECK(m.static_extent(1) == etl::dynamic_extent);
        CHECK(m.extent(1) == 0);
    }

    // 1. 2D-Mixed
    {
        auto m = etl::mdspan<T, etl::extents<Index, 2, etl::dynamic_extent>>{};
        CHECK(m.rank() == 2);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == 2);
        CHECK(m.extent(0) == 2);
        CHECK(m.static_extent(1) == etl::dynamic_extent);
        CHECK(m.extent(1) == 0);
    }

    // 2. 1D-Dynamic
    {
        auto buf = etl::array<T, 2>{};
        auto m   = etl::mdspan<T, etl::dextents<Index, 1>>{buf.data(), 2};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 2);
    }

    // 2. 2D-Dynamic
    {
        auto buf = etl::array<T, 2>{};
        auto m   = etl::mdspan<T, etl::dextents<Index, 2>>{buf.data(), 2, 1};
        CHECK(m.rank() == 2);
        CHECK(m.rank_dynamic() == 2);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 2);
        CHECK(m.static_extent(1) == etl::dynamic_extent);
        CHECK(m.extent(1) == 1);
    }

    // 2. 2D-Mixed
    {
        auto buf = etl::array<T, 2>{};
        auto m   = etl::mdspan<T, etl::extents<Index, 2, etl::dynamic_extent>>{buf.data(), 1};
        CHECK(m.rank() == 2);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == 2);
        CHECK(m.extent(0) == 2);
        CHECK(m.static_extent(1) == etl::dynamic_extent);
        CHECK(m.extent(1) == 1);
    }

    // 5. 1D-Dynamic
    {
        auto buf = etl::array<T, 2>{};
        auto ext = etl::dextents<Index, 1>{buf.size()};
        auto m   = etl::mdspan{buf.data(), ext};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 2);
    }

    // 5. 1D-Static
    {
        auto buf = etl::array<T, 2>{};
        auto ext = etl::extents<Index, 2>{};
        auto m   = etl::mdspan{buf.data(), ext};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 0);
        CHECK(m.static_extent(0) == 2);
        CHECK(m.extent(0) == 2);
    }

    // 6. 1D-Dynamic
    {
        auto buf = etl::array<T, 2>{};
        auto map = etl::layout_right::mapping(etl::dextents<Index, 1>{buf.size()});
        auto m   = etl::mdspan{buf.data(), map};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 2);
    }

    // 6. 1D-Static
    {
        auto buf = etl::array<T, 2>{};
        auto map = etl::layout_right::mapping(etl::extents<Index, 2>{});
        auto m   = etl::mdspan{buf.data(), map};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 0);
        CHECK(m.static_extent(0) == 2);
        CHECK(m.extent(0) == 2);
    }

    return true;
}

template <typename Index>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    CHECK(test<char, Index>());
    CHECK(test<char8_t, Index>());
    CHECK(test<char16_t, Index>());
    CHECK(test<char32_t, Index>());

    CHECK(test<unsigned char, Index>());
    CHECK(test<unsigned short, Index>());
    CHECK(test<unsigned int, Index>());
    CHECK(test<unsigned long, Index>());
    CHECK(test<unsigned long long, Index>());

    CHECK(test<signed char, Index>());
    CHECK(test<signed short, Index>());
    CHECK(test<signed int, Index>());
    CHECK(test<signed long, Index>());
    CHECK(test<signed long long, Index>());

    CHECK(test<float, Index>());
    CHECK(test<double, Index>());

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_index_type<unsigned char>());
    CHECK(test_index_type<unsigned short>());
    CHECK(test_index_type<unsigned int>());
    CHECK(test_index_type<unsigned long>());
    CHECK(test_index_type<unsigned long long>());

    CHECK(test_index_type<signed char>());
    CHECK(test_index_type<signed short>());
    CHECK(test_index_type<signed int>());
    CHECK(test_index_type<signed long>());
    CHECK(test_index_type<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
