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

    {
        auto m = etl::mdspan<ElementType, extents_t> {};
        assert(m.rank() == 1);
        assert(m.rank_dynamic() == 1);
        assert(m.static_extent(0) == etl::dynamic_extent);
        assert(m.extent(0) == 0);

        assert(m.empty());
        assert(m.size() == 0); // NOLINT
    }

    {
        auto buffer = etl::array<ElementType, 16> {};
        auto m      = etl::mdspan<ElementType, extents_t> { buffer.data(), buffer.size() };
        assert(m.rank() == 1);
        assert(m.rank_dynamic() == 1);
        assert(m.static_extent(0) == etl::dynamic_extent);
        assert(m.extent(0) == buffer.size());

        assert(not m.empty());
        assert(m.size() == buffer.size());
    }

    {
        auto buffer = etl::array<ElementType, 16> {};
        auto m      = etl::mdspan(buffer.data(), 2, 8);
        assert(m.rank() == 2);
        assert(m.rank_dynamic() == 2);
        assert(m.static_extent(0) == etl::dynamic_extent);
        assert(m.static_extent(1) == etl::dynamic_extent);
        assert(m.extent(0) == 2);
        assert(m.extent(1) == 8);

        assert(not m.empty());
        assert(m.size() == buffer.size());
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    assert(test_mdspan<char, IndexType>());
    assert(test_mdspan<char8_t, IndexType>());
    assert(test_mdspan<char16_t, IndexType>());
    assert(test_mdspan<char32_t, IndexType>());

    assert(test_mdspan<etl::uint8_t, IndexType>());
    assert(test_mdspan<etl::uint16_t, IndexType>());
    assert(test_mdspan<etl::uint32_t, IndexType>());
    assert(test_mdspan<etl::uint64_t, IndexType>());

    assert(test_mdspan<etl::int8_t, IndexType>());
    assert(test_mdspan<etl::int16_t, IndexType>());
    assert(test_mdspan<etl::int32_t, IndexType>());
    assert(test_mdspan<etl::int64_t, IndexType>());

    assert(test_mdspan<float, IndexType>());
    assert(test_mdspan<double, IndexType>());

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    assert(test_index_type<etl::uint8_t>());
    assert(test_index_type<etl::uint16_t>());
    assert(test_index_type<etl::uint32_t>());
    assert(test_index_type<etl::uint64_t>());

    assert(test_index_type<etl::int8_t>());
    assert(test_index_type<etl::int16_t>());
    assert(test_index_type<etl::int32_t>());
    assert(test_index_type<etl::int64_t>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
