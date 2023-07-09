// SPDX-License-Identifier: BSL-1.0

#include <etl/concepts.hpp>
#include <etl/mdspan.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename IndexType>
constexpr auto test_one() -> bool
{
    using extents_2d_t = etl::extents<IndexType, 2, etl::dynamic_extent>;
    using mapping_2d_t = etl::layout_left::mapping<extents_2d_t>;

    static_assert(etl::is_trivial_v<etl::layout_left>);
    static_assert(etl::is_trivially_copyable_v<mapping_2d_t>);

    static_assert(etl::same_as<typename mapping_2d_t::extents_type, extents_2d_t>);
    static_assert(etl::same_as<typename mapping_2d_t::index_type, IndexType>);
    static_assert(etl::same_as<typename mapping_2d_t::size_type, typename extents_2d_t::size_type>);
    static_assert(etl::same_as<typename mapping_2d_t::rank_type, typename extents_2d_t::rank_type>);
    static_assert(etl::same_as<typename mapping_2d_t::layout_type, etl::layout_left>);

    {
        auto const mapping = mapping_2d_t {};
        auto const copy    = mapping;
        assert(copy == mapping);
        static_assert(etl::is_nothrow_default_constructible_v<mapping_2d_t>);
        static_assert(etl::is_nothrow_copy_constructible_v<mapping_2d_t>);
    }

    {
        auto mapping = mapping_2d_t {};
        auto copy    = mapping_2d_t {};
        copy         = mapping;
        assert(copy == mapping);
        static_assert(etl::is_nothrow_copy_assignable_v<mapping_2d_t>);
    }

    {
        auto ext     = extents_2d_t(42);
        auto mapping = mapping_2d_t(ext);
        assert(mapping.extents() == ext);
        static_assert(etl::is_nothrow_constructible_v<mapping_2d_t, extents_2d_t>);
    }

    {
        assert(mapping_2d_t::is_always_unique());
        assert(mapping_2d_t::is_always_exhaustive());
        assert(mapping_2d_t::is_always_strided());
        assert(mapping_2d_t::is_unique());
        assert(mapping_2d_t::is_exhaustive());
        assert(mapping_2d_t::is_strided());

        assert(mapping_2d_t(extents_2d_t(1)).required_span_size() == 2);
        assert(mapping_2d_t(extents_2d_t(1))(0, 0) == 0);
        assert(mapping_2d_t(extents_2d_t(1))(1, 0) == 1);

        assert(mapping_2d_t(extents_2d_t(42)).required_span_size() == 84);
        assert(mapping_2d_t(extents_2d_t(42))(0, 0) == 0);
        assert(mapping_2d_t(extents_2d_t(42))(1, 0) == 1);
        assert(mapping_2d_t(extents_2d_t(42))(0, 1) == 2);
        assert(mapping_2d_t(extents_2d_t(42))(1, 1) == 3);
    }

    {
        using extents_3d_t = etl::extents<IndexType, etl::dynamic_extent, 2, etl::dynamic_extent>;
        using mapping_3d_t = etl::layout_left::mapping<extents_3d_t>;

        assert(mapping_3d_t::is_always_unique());
        assert(mapping_3d_t::is_always_exhaustive());
        assert(mapping_3d_t::is_always_strided());
        assert(mapping_3d_t::is_unique());
        assert(mapping_3d_t::is_exhaustive());
        assert(mapping_3d_t::is_strided());

        assert(mapping_3d_t(extents_3d_t(1, 1)).required_span_size() == 2);
        assert(mapping_3d_t(extents_3d_t(1, 2)).required_span_size() == 4);
        assert(mapping_3d_t(extents_3d_t(2, 2)).required_span_size() == 8);
    }

    {
        using extents_4d_t = etl::extents<IndexType, etl::dynamic_extent, etl::dynamic_extent, 2, etl::dynamic_extent>;
        using mapping_4d_t = etl::layout_left::mapping<extents_4d_t>;

        assert(mapping_4d_t::is_always_unique());
        assert(mapping_4d_t::is_always_exhaustive());
        assert(mapping_4d_t::is_always_strided());
        assert(mapping_4d_t::is_unique());
        assert(mapping_4d_t::is_exhaustive());
        assert(mapping_4d_t::is_strided());

        assert(mapping_4d_t(extents_4d_t(1, 1, 1)).required_span_size() == 2);
        assert(mapping_4d_t(extents_4d_t(1, 1, 2)).required_span_size() == 4);
        assert(mapping_4d_t(extents_4d_t(3, 2, 2)).required_span_size() == 24);
    }

    return true;
}

constexpr auto test_layout_left() -> bool
{
    assert(test_one<etl::uint8_t>());
    assert(test_one<etl::uint16_t>());
    assert(test_one<etl::uint32_t>());
    assert(test_one<etl::uint64_t>());

    assert(test_one<etl::int8_t>());
    assert(test_one<etl::int16_t>());
    assert(test_one<etl::int32_t>());
    assert(test_one<etl::int64_t>());

    assert(test_one<etl::size_t>());
    assert(test_one<etl::ptrdiff_t>());
    return true;
}

auto main() -> int
{
    assert(test_layout_left());
    static_assert(test_layout_left());
    return 0;
}
