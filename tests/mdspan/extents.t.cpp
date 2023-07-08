// SPDX-License-Identifier: BSL-1.0

#include <etl/concepts.hpp>
#include <etl/mdspan.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename IndexType>
constexpr auto test_one() -> bool
{
    using unsigned_t = etl::make_unsigned_t<IndexType>;
    using extents_t  = etl::extents<IndexType, 2, etl::dynamic_extent>;

    static_assert(etl::is_trivially_copyable_v<extents_t>);
    static_assert(etl::is_nothrow_copy_constructible_v<extents_t>);
    static_assert(etl::is_nothrow_move_constructible_v<extents_t>);
    static_assert(etl::is_nothrow_copy_assignable_v<extents_t>);
    static_assert(etl::is_nothrow_move_assignable_v<extents_t>);
    static_assert(etl::is_nothrow_swappable_v<extents_t>);

    assert(etl::same_as<typename extents_t::index_type, IndexType>);
    assert(etl::same_as<typename extents_t::size_type, unsigned_t>);
    assert(etl::same_as<typename extents_t::rank_type, etl::size_t>);

    auto ed1 = etl::extents<IndexType, etl::dynamic_extent> {};
    assert(ed1.rank() == 1);
    assert(ed1.rank_dynamic() == 1);
    assert(ed1.static_extent(0) == etl::dynamic_extent);

    auto ed2 = etl::extents<IndexType, etl::dynamic_extent, etl::dynamic_extent> {};
    assert(ed2.rank() == 2);
    assert(ed2.rank_dynamic() == 2);
    assert(ed2.static_extent(0) == etl::dynamic_extent);
    assert(ed2.static_extent(1) == etl::dynamic_extent);

    auto es1 = etl::extents<IndexType, 2> {};
    assert(es1.rank() == 1);
    assert(es1.rank_dynamic() == 0);
    assert(es1.static_extent(0) == 2);

    auto es2 = etl::extents<IndexType, 2, 4> {};
    assert(es2.rank() == 2);
    assert(es2.rank_dynamic() == 0);
    assert(es2.static_extent(0) == 2);
    assert(es2.static_extent(1) == 4);

    auto es3 = etl::extents<IndexType, 2, 2, 2> {};
    assert(es3.rank() == 3);
    assert(es3.rank_dynamic() == 0);

    auto eds2 = etl::extents<IndexType, 2, etl::dynamic_extent> {};
    assert(eds2.rank() == 2);
    assert(eds2.rank_dynamic() == 1);

    return true;
}

constexpr auto test_extents() -> bool
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
    assert(test_extents());
    static_assert(test_extents());
    return 0;
}
