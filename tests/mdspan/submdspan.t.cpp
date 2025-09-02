// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/concepts.hpp>
    #include <etl/iterator.hpp>
    #include <etl/mdspan.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename Int>
static constexpr auto test_strided_slice() -> bool
{
    auto slice = etl::strided_slice{Int(1), Int(2), Int(3)};
    CHECK_SAME_TYPE(typename decltype(slice)::offset_type, Int);
    CHECK_SAME_TYPE(typename decltype(slice)::extent_type, Int);
    CHECK_SAME_TYPE(typename decltype(slice)::stride_type, Int);

    CHECK(slice.offset == Int(1));
    CHECK(slice.extent == Int(2));
    CHECK(slice.stride == Int(3));

    return true;
}

static constexpr auto test_submdspan_extents() -> bool
{
    auto ext = etl::extents<int, 2, 3>{};

    auto col0Ext = etl::submdspan_extents(ext, etl::full_extent, 0);
    CHECK(col0Ext.rank() == 1);
    CHECK(col0Ext.extent(0) == 2);

    auto col1Ext = etl::submdspan_extents(ext, etl::full_extent, 1);
    CHECK(col1Ext.rank() == 1);
    CHECK(col1Ext.extent(0) == 2);

    auto col2Ext = etl::submdspan_extents(ext, etl::full_extent, 2);
    CHECK(col2Ext.rank() == 1);
    CHECK(col2Ext.extent(0) == 2);

    auto row0Ext = etl::submdspan_extents(ext, 0, etl::full_extent);
    CHECK(row0Ext.rank() == 1);
    CHECK(row0Ext.extent(0) == 3);

    auto row1Ext = etl::submdspan_extents(ext, 1, etl::full_extent);
    CHECK(row1Ext.rank() == 1);
    CHECK(row1Ext.extent(0) == 3);

    return true;
}

static constexpr auto test() -> bool
{
    CHECK(test_strided_slice<signed char>());
    CHECK(test_strided_slice<signed short>());
    CHECK(test_strided_slice<signed int>());
    CHECK(test_strided_slice<signed long>());
    CHECK(test_strided_slice<signed long long>());

    CHECK(test_strided_slice<unsigned char>());
    CHECK(test_strided_slice<unsigned short>());
    CHECK(test_strided_slice<unsigned int>());
    CHECK(test_strided_slice<unsigned long>());
    CHECK(test_strided_slice<unsigned long long>());

    CHECK(test_submdspan_extents());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
