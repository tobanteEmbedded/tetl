// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename ElementType, typename IndexType>
[[nodiscard]] constexpr auto test_mdspan() -> bool
{
    using size_type = etl::make_unsigned_t<IndexType>;
    using extents_t = etl::extents<IndexType, etl::dynamic_extent>;
    using mdspan_t  = etl::mdspan<ElementType, extents_t>;

    static_assert(etl::same_as<typename mdspan_t::element_type, ElementType>);
    static_assert(etl::same_as<typename mdspan_t::value_type, ElementType>);
    static_assert(etl::same_as<typename mdspan_t::size_type, size_type>);
    static_assert(etl::same_as<typename mdspan_t::index_type, IndexType>);

    ASSERT_NOEXCEPT(etl::declval<mdspan_t>().rank());
    ASSERT_NOEXCEPT(etl::declval<mdspan_t>().rank_dynamic());
    ASSERT_NOEXCEPT(etl::declval<mdspan_t>().static_extent(0));
    ASSERT_NOEXCEPT(etl::declval<mdspan_t>().extent(0));

    {
        auto m = etl::mdspan<ElementType, extents_t>{};
        ASSERT(m.rank() == 1);
        ASSERT(m.rank_dynamic() == 1);
        ASSERT(m.static_extent(0) == etl::dynamic_extent);
        ASSERT(m.extent(0) == 0);

        ASSERT(m.empty());
        ASSERT(m.size() == 0); // NOLINT
    }

    {
        auto buffer = etl::array<ElementType, 16>{ElementType(1)};
        auto m      = etl::mdspan<ElementType, extents_t>{buffer.data(), buffer.size()};
        ASSERT(m.rank() == 1);
        ASSERT(m.rank_dynamic() == 1);
        ASSERT(m.static_extent(0) == etl::dynamic_extent);
        ASSERT(m.extent(0) == buffer.size());

        ASSERT(not m.empty());
        ASSERT(m.size() == buffer.size());

        ASSERT(m(0) == ElementType(1));
        ASSERT(m(1) == ElementType(0));
#if defined(__cpp_multidimensional_subscript)
        ASSERT(m[0] == ElementType(1));
        ASSERT(m[1] == ElementType(0));
#endif
    }

    {
        auto buffer = etl::array<ElementType, 16>{ElementType(1)};
        auto m      = etl::mdspan(buffer.data(), 2, 8);
        ASSERT(m.rank() == 2);
        ASSERT(m.rank_dynamic() == 2);
        ASSERT(m.static_extent(0) == etl::dynamic_extent);
        ASSERT(m.static_extent(1) == etl::dynamic_extent);
        ASSERT(m.extent(0) == 2);
        ASSERT(m.extent(1) == 8);

        ASSERT(not m.empty());
        ASSERT(m.size() == buffer.size());

        ASSERT(m(0, 0) == ElementType(1));
        ASSERT(m(0, 1) == ElementType(0));
#if defined(__cpp_multidimensional_subscript)
        ASSERT(m[0, 0] == ElementType(1));
        ASSERT(m[0, 1] == ElementType(0));
#endif
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    ASSERT(test_mdspan<char, IndexType>());
    ASSERT(test_mdspan<char8_t, IndexType>());
    ASSERT(test_mdspan<char16_t, IndexType>());
    ASSERT(test_mdspan<char32_t, IndexType>());

    ASSERT(test_mdspan<etl::uint8_t, IndexType>());
    ASSERT(test_mdspan<etl::uint16_t, IndexType>());
    ASSERT(test_mdspan<etl::uint32_t, IndexType>());
    ASSERT(test_mdspan<etl::uint64_t, IndexType>());

    ASSERT(test_mdspan<etl::int8_t, IndexType>());
    ASSERT(test_mdspan<etl::int16_t, IndexType>());
    ASSERT(test_mdspan<etl::int32_t, IndexType>());
    ASSERT(test_mdspan<etl::int64_t, IndexType>());

    ASSERT(test_mdspan<float, IndexType>());
    ASSERT(test_mdspan<double, IndexType>());

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    ASSERT(test_index_type<etl::uint8_t>());
    ASSERT(test_index_type<etl::uint16_t>());
    ASSERT(test_index_type<etl::uint32_t>());
    ASSERT(test_index_type<etl::uint64_t>());

    ASSERT(test_index_type<etl::int8_t>());
    ASSERT(test_index_type<etl::int16_t>());
    ASSERT(test_index_type<etl::int32_t>());
    ASSERT(test_index_type<etl::int64_t>());

    return true;
}

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
