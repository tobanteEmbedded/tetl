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

template <typename IndexType>
static constexpr auto test_one() -> bool
{
    using unsigned_t = etl::make_unsigned_t<IndexType>;
    using extents_t  = etl::extents<IndexType, 2, etl::dynamic_extent>;

    CHECK(etl::is_trivially_copyable_v<extents_t>);
    CHECK(etl::is_nothrow_copy_constructible_v<extents_t>);
    CHECK(etl::is_nothrow_move_constructible_v<extents_t>);
    CHECK(etl::is_nothrow_copy_assignable_v<extents_t>);
    CHECK(etl::is_nothrow_move_assignable_v<extents_t>);
    CHECK(etl::is_nothrow_swappable_v<extents_t>);

    CHECK_SAME_TYPE(typename extents_t::index_type, IndexType);
    CHECK_SAME_TYPE(typename extents_t::size_type, unsigned_t);
    CHECK_SAME_TYPE(typename extents_t::rank_type, etl::size_t);

    {
        // rank 1, all dynamic
        auto e = etl::extents<IndexType, etl::dynamic_extent>(42);
        CHECK(e.rank() == 1);
        CHECK(e.rank_dynamic() == 1);
        CHECK(e.static_extent(0) == etl::dynamic_extent);
        CHECK(e.extent(0) == 42);

        auto other = etl::extents<unsigned_t, etl::dynamic_extent>{e};
        CHECK(other.rank() == 1);
        CHECK(other.rank_dynamic() == 1);
        CHECK(other.static_extent(0) == etl::dynamic_extent);
        CHECK(other.extent(0) == 42);

        CHECK(e == other);

        auto const lhs = etl::extents<IndexType, etl::dynamic_extent>{42};
        auto const rhs = etl::extents<IndexType, etl::dynamic_extent>{88};
        CHECK(lhs != rhs);
        CHECK_FALSE(lhs == rhs);
    }

    {
        // rank 2, all dynamic
        auto e = etl::extents<IndexType, etl::dynamic_extent, etl::dynamic_extent>{42, 43};
        CHECK(e.rank() == 2);
        CHECK(e.rank_dynamic() == 2);
        CHECK(e.static_extent(0) == etl::dynamic_extent);
        CHECK(e.static_extent(1) == etl::dynamic_extent);
        CHECK(e.extent(0) == 42);
        CHECK(e.extent(1) == 43);

        auto other = etl::extents<unsigned_t, etl::dynamic_extent, etl::dynamic_extent>{e};
        CHECK(other.rank() == 2);
        CHECK(other.rank_dynamic() == 2);
        CHECK(other.static_extent(0) == etl::dynamic_extent);
        CHECK(other.static_extent(1) == etl::dynamic_extent);
        CHECK(other.extent(0) == 42);
        CHECK(other.extent(1) == 43);

        CHECK(e == other);

        auto const lhs = etl::extents<IndexType, etl::dynamic_extent, etl::dynamic_extent>{42, 43};
        auto const rhs = etl::extents<IndexType, etl::dynamic_extent, etl::dynamic_extent>{88, 89};
        CHECK(lhs != rhs);
        CHECK_FALSE(lhs == rhs);
    }

    {
        // rank 1, all static
        auto e = etl::extents<IndexType, 2>{};
        CHECK(e.rank() == 1);
        CHECK(e.rank_dynamic() == 0);
        CHECK(e.static_extent(0) == 2);
        CHECK(e.extent(0) == 2);

        auto other = etl::extents<unsigned_t, 2>(e);
        CHECK(other.rank() == 1);
        CHECK(other.rank_dynamic() == 0);
        CHECK(other.static_extent(0) == 2);
        CHECK(other.extent(0) == 2);

        CHECK(e == other);
    }

    {
        // rank 2, all static
        auto e = etl::extents<IndexType, 2, 4>{};
        CHECK(e.rank() == 2);
        CHECK(e.rank_dynamic() == 0);
        CHECK(e.static_extent(0) == 2);
        CHECK(e.static_extent(1) == 4);
        CHECK(e.extent(0) == 2);
        CHECK(e.extent(1) == 4);
    }

    {
        // rank 3, all static
        auto e = etl::extents<IndexType, 1, 2, 3>{};
        CHECK(e.rank() == 3);
        CHECK(e.rank_dynamic() == 0);
        CHECK(e.static_extent(0) == 1);
        CHECK(e.static_extent(1) == 2);
        CHECK(e.static_extent(2) == 3);
        CHECK(e.extent(0) == 1);
        CHECK(e.extent(1) == 2);
        CHECK(e.extent(2) == 3);
    }

    {
        // rank 2, mixed
        auto e = etl::extents<IndexType, 2, etl::dynamic_extent>(42);
        CHECK(e.rank() == 2);
        CHECK(e.rank_dynamic() == 1);
        CHECK(e.static_extent(0) == 2);
        CHECK(e.static_extent(1) == etl::dynamic_extent);
        CHECK(e.extent(0) == 2);
        CHECK(e.extent(1) == 42);

        auto other = etl::extents<unsigned_t, 2, etl::dynamic_extent>(e);
        CHECK(other.rank() == 2);
        CHECK(other.rank_dynamic() == 1);
        CHECK(other.static_extent(0) == 2);
        CHECK(other.static_extent(1) == etl::dynamic_extent);
        CHECK(other.extent(0) == 2);
        CHECK(other.extent(1) == 42);

        CHECK(e == other);
    }

    return true;
}

static constexpr auto test_extents() -> bool
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
    STATIC_CHECK(test_extents());
    return 0;
}
