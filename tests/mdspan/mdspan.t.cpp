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

    CHECK_SAME_TYPE(typename mdspan_t::element_type, ElementType);
    CHECK_SAME_TYPE(typename mdspan_t::value_type, ElementType);
    CHECK_SAME_TYPE(typename mdspan_t::size_type, size_type);
    CHECK_SAME_TYPE(typename mdspan_t::index_type, IndexType);

    CHECK_NOEXCEPT(etl::declval<mdspan_t>().rank());
    CHECK_NOEXCEPT(etl::declval<mdspan_t>().rank_dynamic());
    CHECK_NOEXCEPT(etl::declval<mdspan_t>().static_extent(0));
    CHECK_NOEXCEPT(etl::declval<mdspan_t>().extent(0));

    {
        auto m = etl::mdspan<ElementType, extents_t>{};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == 0);

        CHECK(m.empty());
        CHECK(m.size() == 0); // NOLINT
    }

    {
        auto buffer = etl::array<ElementType, 16>{ElementType(1)};
        auto m      = etl::mdspan<ElementType, extents_t>{buffer.data(), buffer.size()};
        CHECK(m.rank() == 1);
        CHECK(m.rank_dynamic() == 1);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.extent(0) == buffer.size());

        CHECK(not m.empty());
        CHECK(m.size() == buffer.size());

        CHECK(m(0) == ElementType(1));
        CHECK(m(1) == ElementType(0));
#if defined(__cpp_multidimensional_subscript)
        CHECK(m[0] == ElementType(1));
        CHECK(m[1] == ElementType(0));
#endif
    }

    {
        auto buffer = etl::array<ElementType, 16>{ElementType(1)};
        auto m      = etl::mdspan(buffer.data(), 2, 8);
        CHECK(m.rank() == 2);
        CHECK(m.rank_dynamic() == 2);
        CHECK(m.static_extent(0) == etl::dynamic_extent);
        CHECK(m.static_extent(1) == etl::dynamic_extent);
        CHECK(m.extent(0) == 2);
        CHECK(m.extent(1) == 8);

        CHECK(not m.empty());
        CHECK(m.size() == buffer.size());

        CHECK(m(0, 0) == ElementType(1));
        CHECK(m(0, 1) == ElementType(0));
#if defined(__cpp_multidimensional_subscript)
        CHECK(m[0, 0] == ElementType(1));
        CHECK(m[0, 1] == ElementType(0));
#endif
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    CHECK(test_mdspan<char, IndexType>());
    CHECK(test_mdspan<char8_t, IndexType>());
    CHECK(test_mdspan<char16_t, IndexType>());
    CHECK(test_mdspan<char32_t, IndexType>());

    CHECK(test_mdspan<etl::uint8_t, IndexType>());
    CHECK(test_mdspan<etl::uint16_t, IndexType>());
    CHECK(test_mdspan<etl::uint32_t, IndexType>());
    CHECK(test_mdspan<etl::uint64_t, IndexType>());

    CHECK(test_mdspan<etl::int8_t, IndexType>());
    CHECK(test_mdspan<etl::int16_t, IndexType>());
    CHECK(test_mdspan<etl::int32_t, IndexType>());
    CHECK(test_mdspan<etl::int64_t, IndexType>());

    CHECK(test_mdspan<float, IndexType>());
    CHECK(test_mdspan<double, IndexType>());

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_index_type<etl::uint8_t>());
    CHECK(test_index_type<etl::uint16_t>());
    CHECK(test_index_type<etl::uint32_t>());
    CHECK(test_index_type<etl::uint64_t>());

    CHECK(test_index_type<etl::int8_t>());
    CHECK(test_index_type<etl::int16_t>());
    CHECK(test_index_type<etl::int32_t>());
    CHECK(test_index_type<etl::int64_t>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
