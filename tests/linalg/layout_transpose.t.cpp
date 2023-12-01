// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include "testing/testing.hpp"

template <typename IndexType>
[[nodiscard]] static constexpr auto test_layout_transpose() -> bool
{
    {
        using extents_t   = etl::extents<IndexType, 2, 3>;
        using expected_t  = etl::extents<IndexType, 3, 2>;
        using transpose_t = etl::linalg::detail::transpose_extents_t<extents_t>;
        static_assert(etl::same_as<expected_t, transpose_t>);
    }

    {
        // static extents
        using extents_t       = etl::extents<IndexType, 2, 3>;
        auto const ext        = extents_t {};
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        assert(transposed.static_extent(0) == ext.static_extent(1));
        assert(transposed.static_extent(1) == ext.static_extent(0));
        assert(transposed.extent(0) == ext.extent(1));
        assert(transposed.extent(1) == ext.extent(0));
        assert(transposed.extent(0) == transposed.static_extent(0));
        assert(transposed.extent(1) == transposed.static_extent(1));
    }

    {
        // dynamic extents
        using extents_t       = etl::dextents<IndexType, 2>;
        auto const ext        = extents_t {IndexType(2), IndexType(3)};
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        assert(transposed.static_extent(0) == etl::dynamic_extent);
        assert(transposed.static_extent(1) == etl::dynamic_extent);
        assert(transposed.static_extent(0) == ext.static_extent(1));
        assert(transposed.static_extent(1) == ext.static_extent(0));
        assert(transposed.extent(0) == ext.extent(1));
        assert(transposed.extent(1) == ext.extent(0));
        assert(transposed.extent(0) != transposed.static_extent(0));
        assert(transposed.extent(1) != transposed.static_extent(1));

        auto const mapping = etl::linalg::layout_transpose<etl::layout_right>::mapping<extents_t> {ext};
        assert(mapping.extents().extent(0) == IndexType(3));
        assert(mapping.extents().extent(1) == IndexType(2));
        assert(mapping.required_span_size() == 6);
        assert(mapping.is_always_unique());
        assert(mapping.is_always_strided());
        assert(mapping.is_unique());
        assert(mapping.is_strided());
    }

    {
        // mixed extents
        using extents_t       = etl::extents<IndexType, 2, etl::dynamic_extent>;
        auto const ext        = extents_t {IndexType(3)};
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        assert(transposed.static_extent(0) == etl::dynamic_extent);
        assert(transposed.static_extent(1) != etl::dynamic_extent);
        assert(transposed.static_extent(0) == ext.static_extent(1));
        assert(transposed.static_extent(1) == ext.static_extent(0));
        assert(transposed.extent(0) == ext.extent(1));
        assert(transposed.extent(1) == ext.extent(0));
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    assert(test_layout_transpose<unsigned char>());
    assert(test_layout_transpose<unsigned short>());
    assert(test_layout_transpose<unsigned int>());
    assert(test_layout_transpose<unsigned long>());
    assert(test_layout_transpose<unsigned long long>());

    assert(test_layout_transpose<signed char>());
    assert(test_layout_transpose<signed short>());
    assert(test_layout_transpose<signed int>());
    assert(test_layout_transpose<signed long>());
    assert(test_layout_transpose<signed long long>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
