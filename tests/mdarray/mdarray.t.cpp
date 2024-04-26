// SPDX-License-Identifier: BSL-1.0

#include <etl/mdarray.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T, typename Index>
[[nodiscard]] constexpr auto test_mdarray() -> bool
{
    // traits
    {
        using matrix = etl::mdarray<T, etl::extents<Index, 2, 3>, etl::layout_left, etl::array<T, 6>>;
        CHECK_SAME_TYPE(typename matrix::value_type, T);
        CHECK_SAME_TYPE(typename matrix::element_type, T);
        CHECK_SAME_TYPE(typename matrix::container_type, etl::array<T, 6>);

        CHECK(matrix::rank() == 2);
        CHECK(matrix::rank_dynamic() == 0);
        CHECK(matrix::static_extent(0) == 2);
        CHECK(matrix::static_extent(1) == 3);
    }

    // ctor(index...)
    {
        using extents       = etl::dextents<Index, 2>;
        using array_matrix  = etl::mdarray<T, extents, etl::layout_left, etl::array<T, 6>>;
        using vector_matrix = etl::mdarray<T, extents, etl::layout_left, etl::static_vector<T, 6>>;

        auto am = array_matrix{2, 3};
        CHECK(am.extents().extent(0) == Index(2));
        CHECK(am.extents().extent(1) == Index(3));

        auto vm = vector_matrix{2, 3};
        CHECK(vm.extents().extent(0) == Index(2));
        CHECK(vm.extents().extent(1) == Index(3));
    }

    return true;
}

template <typename Index>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    CHECK(test_mdarray<char, Index>());
    CHECK(test_mdarray<char8_t, Index>());
    CHECK(test_mdarray<char16_t, Index>());
    CHECK(test_mdarray<char32_t, Index>());

    CHECK(test_mdarray<etl::uint8_t, Index>());
    CHECK(test_mdarray<etl::uint16_t, Index>());
    CHECK(test_mdarray<etl::uint32_t, Index>());
    CHECK(test_mdarray<etl::uint64_t, Index>());

    CHECK(test_mdarray<etl::int8_t, Index>());
    CHECK(test_mdarray<etl::int16_t, Index>());
    CHECK(test_mdarray<etl::int32_t, Index>());
    CHECK(test_mdarray<etl::int64_t, Index>());

    CHECK(test_mdarray<float, Index>());
    CHECK(test_mdarray<double, Index>());

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_index_type<etl::uint8_t>());
    CHECK(test_index_type<etl::uint16_t>());
    CHECK(test_index_type<etl::uint32_t>());
    CHECK(test_index_type<etl::uint64_t>());

    CHECK(test_index_type<etl::int8_t>());
    CHECK(test_index_type<etl::int16_t>());
    CHECK(test_index_type<etl::int32_t>());
    CHECK(test_index_type<etl::int64_t>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
