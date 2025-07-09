// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.concepts;
import etl.cstddef;
import etl.cstdint;
import etl.iterator;
import etl.mdspan;
import etl.type_traits;
#else
    #include <etl/array.hpp>
    #include <etl/concepts.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/iterator.hpp>
    #include <etl/mdspan.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename IndexType>
static constexpr auto test_one() -> bool
{
    using extents_2d_t = etl::extents<IndexType, 2, etl::dynamic_extent>;
    using mapping_2d_t = etl::layout_left::mapping<extents_2d_t>;

    CHECK(etl::is_trivial_v<etl::layout_left>);
    CHECK(etl::is_trivially_copyable_v<mapping_2d_t>);

    CHECK_SAME_TYPE(typename mapping_2d_t::extents_type, extents_2d_t);
    CHECK_SAME_TYPE(typename mapping_2d_t::index_type, IndexType);
    CHECK_SAME_TYPE(typename mapping_2d_t::size_type, typename extents_2d_t::size_type);
    CHECK_SAME_TYPE(typename mapping_2d_t::rank_type, typename extents_2d_t::rank_type);
    CHECK_SAME_TYPE(typename mapping_2d_t::layout_type, etl::layout_left);

    {
        auto const mapping = mapping_2d_t{};
        auto const copy    = mapping;
        CHECK(copy == mapping);
        CHECK(etl::is_nothrow_default_constructible_v<mapping_2d_t>);
        CHECK(etl::is_nothrow_copy_constructible_v<mapping_2d_t>);
    }

    {
        auto mapping = mapping_2d_t{};
        auto copy    = mapping_2d_t{};
        copy         = mapping;
        CHECK(copy == mapping);
        CHECK(etl::is_nothrow_copy_assignable_v<mapping_2d_t>);
    }

    {
        auto ext     = extents_2d_t(42);
        auto mapping = mapping_2d_t(ext);
        CHECK(mapping.extents() == ext);
        CHECK(mapping.stride(0) == 1);
        CHECK(mapping.stride(1) == 2);
        CHECK(etl::is_nothrow_constructible_v<mapping_2d_t, extents_2d_t>);
    }

    {
        CHECK(mapping_2d_t::is_always_unique());
        CHECK(mapping_2d_t::is_always_exhaustive());
        CHECK(mapping_2d_t::is_always_strided());
        CHECK(mapping_2d_t::is_unique());
        CHECK(mapping_2d_t::is_exhaustive());
        CHECK(mapping_2d_t::is_strided());

        CHECK(mapping_2d_t(extents_2d_t(1)).required_span_size() == 2);
        CHECK(mapping_2d_t(extents_2d_t(1))(0, 0) == 0);
        CHECK(mapping_2d_t(extents_2d_t(1))(1, 0) == 1);

        CHECK(mapping_2d_t(extents_2d_t(42)).required_span_size() == 84);
        CHECK(mapping_2d_t(extents_2d_t(42))(0, 0) == 0);
        CHECK(mapping_2d_t(extents_2d_t(42))(1, 0) == 1);
        CHECK(mapping_2d_t(extents_2d_t(42))(0, 1) == 2);
        CHECK(mapping_2d_t(extents_2d_t(42))(1, 1) == 3);
    }

    {
        using extents_3d_t = etl::extents<IndexType, etl::dynamic_extent, 2, etl::dynamic_extent>;
        using mapping_3d_t = etl::layout_left::mapping<extents_3d_t>;

        CHECK(mapping_3d_t::is_always_unique());
        CHECK(mapping_3d_t::is_always_exhaustive());
        CHECK(mapping_3d_t::is_always_strided());
        CHECK(mapping_3d_t::is_unique());
        CHECK(mapping_3d_t::is_exhaustive());
        CHECK(mapping_3d_t::is_strided());

        CHECK(mapping_3d_t(extents_3d_t(1, 1)).required_span_size() == 2);
        CHECK(mapping_3d_t(extents_3d_t(1, 2)).required_span_size() == 4);
        CHECK(mapping_3d_t(extents_3d_t(2, 2)).required_span_size() == 8);
    }

    {
        using extents_4d_t = etl::extents<IndexType, etl::dynamic_extent, etl::dynamic_extent, 2, etl::dynamic_extent>;
        using mapping_4d_t = etl::layout_left::mapping<extents_4d_t>;

        CHECK(mapping_4d_t::is_always_unique());
        CHECK(mapping_4d_t::is_always_exhaustive());
        CHECK(mapping_4d_t::is_always_strided());
        CHECK(mapping_4d_t::is_unique());
        CHECK(mapping_4d_t::is_exhaustive());
        CHECK(mapping_4d_t::is_strided());

        CHECK(mapping_4d_t(extents_4d_t(1, 1, 1)).required_span_size() == 2);
        CHECK(mapping_4d_t(extents_4d_t(1, 1, 2)).required_span_size() == 4);
        CHECK(mapping_4d_t(extents_4d_t(3, 2, 2)).required_span_size() == 24);
    }

    return true;
}

static constexpr auto test_layout_left() -> bool
{
    CHECK(test_one<etl::uint8_t>());
    CHECK(test_one<etl::uint16_t>());
    CHECK(test_one<etl::uint32_t>());
    CHECK(test_one<etl::uint64_t>());

    CHECK(test_one<etl::int8_t>());
    CHECK(test_one<etl::int16_t>());
    CHECK(test_one<etl::int32_t>());
    CHECK(test_one<etl::int64_t>());

    CHECK(test_one<etl::size_t>());
    CHECK(test_one<etl::ptrdiff_t>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_layout_left());
    return 0;
}
