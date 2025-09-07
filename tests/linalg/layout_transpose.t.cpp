// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/concepts.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

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
        auto const ext        = extents_t{};
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        CHECK(transposed.static_extent(0) == ext.static_extent(1));
        CHECK(transposed.static_extent(1) == ext.static_extent(0));
        CHECK(transposed.extent(0) == ext.extent(1));
        CHECK(transposed.extent(1) == ext.extent(0));
        CHECK(transposed.extent(0) == transposed.static_extent(0));
        CHECK(transposed.extent(1) == transposed.static_extent(1));
    }

    {
        // dynamic extents
        using extents_t       = etl::dextents<IndexType, 2>;
        auto const ext        = extents_t{IndexType(2), IndexType(3)};
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        CHECK(transposed.static_extent(0) == etl::dynamic_extent);
        CHECK(transposed.static_extent(1) == etl::dynamic_extent);
        CHECK(transposed.static_extent(0) == ext.static_extent(1));
        CHECK(transposed.static_extent(1) == ext.static_extent(0));
        CHECK(transposed.extent(0) == ext.extent(1));
        CHECK(transposed.extent(1) == ext.extent(0));
        CHECK(transposed.extent(0) != static_cast<IndexType>(transposed.static_extent(0)));
        CHECK(transposed.extent(1) != static_cast<IndexType>(transposed.static_extent(1)));

        auto const mapping = etl::linalg::layout_transpose<etl::layout_right>::mapping<extents_t>{ext};
        CHECK(mapping.extents().extent(0) == IndexType(3));
        CHECK(mapping.extents().extent(1) == IndexType(2));
        CHECK(mapping.required_span_size() == 6);
        CHECK(mapping.is_always_unique());
        CHECK(mapping.is_always_strided());
        CHECK(mapping.is_unique());
        CHECK(mapping.is_strided());
    }

    {
        // mixed extents
        using extents_t       = etl::extents<IndexType, 2, etl::dynamic_extent>;
        auto const ext        = extents_t{IndexType(3)};
        auto const transposed = etl::linalg::detail::transpose_extents(ext);
        CHECK(transposed.static_extent(0) == etl::dynamic_extent);
        CHECK(transposed.static_extent(1) != etl::dynamic_extent);
        CHECK(transposed.static_extent(0) == ext.static_extent(1));
        CHECK(transposed.static_extent(1) == ext.static_extent(0));
        CHECK(transposed.extent(0) == ext.extent(1));
        CHECK(transposed.extent(1) == ext.extent(0));
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_layout_transpose<unsigned char>());
    CHECK(test_layout_transpose<unsigned short>());
    CHECK(test_layout_transpose<unsigned int>());
    CHECK(test_layout_transpose<unsigned long>());
    CHECK(test_layout_transpose<unsigned long long>());

    CHECK(test_layout_transpose<signed char>());
    CHECK(test_layout_transpose<signed short>());
    CHECK(test_layout_transpose<signed int>());
    CHECK(test_layout_transpose<signed long>());
    CHECK(test_layout_transpose<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
