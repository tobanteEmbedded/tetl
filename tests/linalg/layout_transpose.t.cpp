// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include "testing/testing.hpp"

template <typename IndexType>
[[nodiscard]] static constexpr auto test_layout_transpose() -> bool
{
    using extents_type                    = etl::extents<IndexType, 2, 3>;
    using expected_transpose_extents_type = etl::extents<IndexType, 3, 2>;
    using transpose_extents_type          = etl::linalg::detail::transpose_extents_t<extents_type>;
    static_assert(etl::same_as<expected_transpose_extents_type, transpose_extents_type>);

    {
        // static extents
        auto const ext        = etl::extents<IndexType, 2, 3> {};
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
        auto const ext        = etl::dextents<IndexType, 2> { IndexType(2), IndexType(3) };
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        assert(transposed.static_extent(0) == etl::dynamic_extent);
        assert(transposed.static_extent(1) == etl::dynamic_extent);
        assert(transposed.static_extent(0) == ext.static_extent(1));
        assert(transposed.static_extent(1) == ext.static_extent(0));
        assert(transposed.extent(0) == ext.extent(1));
        assert(transposed.extent(1) == ext.extent(0));
        assert(transposed.extent(0) != transposed.static_extent(0));
        assert(transposed.extent(1) != transposed.static_extent(1));
    }

    {
        // mixed extents
        auto const ext        = etl::extents<IndexType, 2, etl::dynamic_extent> { IndexType(3) };
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
