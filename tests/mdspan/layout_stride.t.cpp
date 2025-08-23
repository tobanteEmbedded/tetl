// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/concepts.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/iterator.hpp>
    #include <etl/mdspan.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename Index>
static constexpr auto test() -> bool
{
    using extents_1d = etl::dextents<Index, 1>;
    using mapping_1d = etl::layout_stride::mapping<extents_1d>;

    CHECK(etl::is_trivial_v<etl::layout_stride>);
    CHECK(etl::is_trivially_copyable_v<mapping_1d>);
    CHECK(etl::is_nothrow_default_constructible_v<mapping_1d>);
    CHECK(etl::is_nothrow_copy_constructible_v<mapping_1d>);

    CHECK_SAME_TYPE(typename mapping_1d::extents_type, extents_1d);
    CHECK_SAME_TYPE(typename mapping_1d::index_type, Index);
    CHECK_SAME_TYPE(typename mapping_1d::size_type, typename extents_1d::size_type);
    CHECK_SAME_TYPE(typename mapping_1d::rank_type, typename extents_1d::rank_type);
    CHECK_SAME_TYPE(typename mapping_1d::layout_type, etl::layout_stride);

    CHECK(mapping_1d::is_always_unique());
    CHECK(mapping_1d::is_always_strided());
    CHECK_FALSE(mapping_1d::is_always_exhaustive());

    CHECK(mapping_1d::is_unique());
    CHECK(mapping_1d::is_strided());
    // CHECK_FALSE(mapping_1d::is_exhaustive());

    {
        auto const ext     = extents_1d(Index(64));
        auto const strides = etl::array{Index(2)};
        auto const mapping = mapping_1d(ext, strides);
        CHECK(mapping.extents() == ext);
        CHECK(mapping.strides() == strides);
        CHECK(mapping.stride(0) == strides[0]);
        CHECK(mapping(0) == Index(0));
        CHECK(mapping(1) == Index(2));
        CHECK(mapping(2) == Index(4));
    }

    {
        auto const ext     = extents_1d(Index(64));
        auto const strides = etl::array{Index(3)};
        auto const mapping = mapping_1d(ext, strides);
        CHECK(mapping.extents() == ext);
        CHECK(mapping.strides() == strides);
        CHECK(mapping.stride(0) == strides[0]);
        CHECK(mapping(0) == Index(0));
        CHECK(mapping(1) == Index(3));
        CHECK(mapping(2) == Index(6));
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());

    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());

    CHECK(test<etl::size_t>());
    CHECK(test<etl::ptrdiff_t>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
