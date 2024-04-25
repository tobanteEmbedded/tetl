// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/array.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T, typename Index>
[[nodiscard]] constexpr auto test() -> bool
{
    using mdspan_type = etl::mdspan<T, etl::extents<Index, etl::dynamic_extent>>;
    CHECK_SAME_TYPE(typename mdspan_type::element_type, T);
    CHECK_SAME_TYPE(typename mdspan_type::value_type, T);
    CHECK_SAME_TYPE(typename mdspan_type::size_type, etl::make_unsigned_t<Index>);
    CHECK_SAME_TYPE(typename mdspan_type::index_type, Index);
    CHECK_NOEXCEPT(etl::declval<mdspan_type>().rank());
    CHECK_NOEXCEPT(etl::declval<mdspan_type>().rank_dynamic());
    CHECK_NOEXCEPT(etl::declval<mdspan_type>().static_extent(0));
    CHECK_NOEXCEPT(etl::declval<mdspan_type>().extent(0));

    {
        auto m = etl::mdspan<T, etl::extents<Index, etl::dynamic_extent>>{};
        CHECK(m.empty());
        CHECK(m.size() == 0); // NOLINT

        CHECK(m.is_unique());
        CHECK(m.is_exhaustive());
        CHECK(m.is_strided());

        CHECK(m.is_always_unique());
        CHECK(m.is_always_exhaustive());
        CHECK(m.is_always_strided());
    }

    {
        auto buffer = etl::array<T, 16>{T(1)};
        auto m      = etl::mdspan<T, etl::extents<Index, etl::dynamic_extent>>{buffer.data(), buffer.size()};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == buffer.size());

        CHECK_FALSE(m.empty());
        CHECK(m.size() == buffer.size());

        CHECK(m(0) == T(1));
        CHECK(m(1) == T(0));
        CHECK(m[etl::array{0}] == T(1));
        CHECK(m[etl::array{1}] == T(0));
#if defined(__cpp_multidimensional_subscript)
        CHECK(m[0] == T(1));
        CHECK(m[1] == T(0));
#endif
    }

    {
        auto buffer = etl::array<T, 16>{T(1)};
        auto m      = etl::mdspan(buffer.data(), 2, 8);
        CHECK(m.rank() == 2);
        CHECK(m.rank_dynamic() == 2);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.static_extent(1) == etl::dynamic_extent);
        CHECK(m.extent(0) == 2);
        CHECK(m.extent(1) == 8);
        CHECK(m.stride(0) == 8);

        CHECK_FALSE(m.empty());
        CHECK(m.size() == buffer.size());

        CHECK(m(0, 0) == T(1));
        CHECK(m(0, 1) == T(0));
        CHECK(m[etl::array{0, 0}] == T(1));
        CHECK(m[etl::array{0, 1}] == T(0));
        CHECK(m[etl::array{0LL, 0LL}] == T(1));
        CHECK(m[etl::array{0LL, 1LL}] == T(0));
#if defined(__cpp_multidimensional_subscript)
        CHECK(m[0, 0] == T(1));
        CHECK(m[0, 1] == T(0));
#endif
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
