// SPDX-License-Identifier: BSL-1.0

#include <etl/mdarray.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename Value, typename Index>
[[nodiscard]] constexpr auto test_mdarray() -> bool
{
    using matrix = etl::mdarray<Value, etl::extents<Index, 2, 3>, etl::layout_left, etl::array<Value, 6>>;
    assert(etl::same_as<typename matrix::value_type, Value>);
    assert(etl::same_as<typename matrix::element_type, Value>);
    assert(etl::same_as<typename matrix::container_type, etl::array<Value, 6>>);

    assert(matrix::rank() == 2);
    assert(matrix::rank_dynamic() == 0);
    assert(matrix::static_extent(0) == 2);
    assert(matrix::static_extent(1) == 3);

    return true;
}

template <typename Index>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    assert(test_mdarray<char, Index>());
    assert(test_mdarray<char8_t, Index>());
    assert(test_mdarray<char16_t, Index>());
    assert(test_mdarray<char32_t, Index>());

    assert(test_mdarray<etl::uint8_t, Index>());
    assert(test_mdarray<etl::uint16_t, Index>());
    assert(test_mdarray<etl::uint32_t, Index>());
    assert(test_mdarray<etl::uint64_t, Index>());

    assert(test_mdarray<etl::int8_t, Index>());
    assert(test_mdarray<etl::int16_t, Index>());
    assert(test_mdarray<etl::int32_t, Index>());
    assert(test_mdarray<etl::int64_t, Index>());

    assert(test_mdarray<float, Index>());
    assert(test_mdarray<double, Index>());

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
