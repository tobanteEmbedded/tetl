// SPDX-License-Identifier: BSL-1.0

#include <etl/mdarray.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T, typename Index>
[[nodiscard]] constexpr auto test() -> bool
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

        CHECK(matrix::is_always_unique());
        CHECK(matrix::is_always_exhaustive());
        CHECK(matrix::is_always_strided());

        CHECK(matrix().is_unique());
        CHECK(matrix().is_exhaustive());
        CHECK(matrix().is_strided());
    }

    // ctor(index...)
    {
        using extents       = etl::dextents<Index, 2>;
        using array_matrix  = etl::mdarray<T, extents, etl::layout_left, etl::array<T, 6>>;
        using vector_matrix = etl::mdarray<T, extents, etl::layout_left, etl::static_vector<T, 6>>;

        auto am = array_matrix{2, 3};
        CHECK_FALSE(am.empty());
        CHECK(am.size() == 6);
        CHECK(am.stride(0) == Index(1));
        CHECK(am.stride(1) == Index(2));
        CHECK(am.extent(0) == Index(2));
        CHECK(am.extent(1) == Index(3));
#if defined(__cpp_multidimensional_subscript)
        am[0, 0] = T(42);
        am[0, 1] = T(43);
        CHECK(etl::as_const(am)[0, 0] == T(42));
        CHECK(etl::as_const(am)[0, 1] == T(43));
#endif

        auto vm = vector_matrix{2, 3};
        CHECK_FALSE(vm.empty());
        CHECK(vm.size() == 6);
        CHECK(vm.stride(0) == Index(1));
        CHECK(vm.stride(1) == Index(2));
        CHECK(vm.extent(0) == Index(2));
        CHECK(vm.extent(1) == Index(3));

        vm[etl::array{0, 0}] = T(99);
        vm[etl::array{0, 1}] = T(100);
        CHECK(etl::as_const(vm)[etl::array{0, 0}] == T(99));
        CHECK(etl::as_const(vm)[etl::array{0, 1}] == T(100));

        auto vm2 = vector_matrix{};
        CHECK(vm2.size() == 0);

        swap(vm, vm2);
        CHECK(vm.size() == 0);
        CHECK(vm2.size() == 6);

        auto c = etl::move(vm2).extract_container();
        CHECK(c[0] == T(99));
    }

    return true;
}

template <typename Index>
[[nodiscard]] constexpr auto test_index_type() -> bool
{
    CHECK(test<char, Index>());
    CHECK(test<char8_t, Index>());
    CHECK(test<char16_t, Index>());
    CHECK(test<char32_t, Index>());

    CHECK(test<etl::uint8_t, Index>());
    CHECK(test<etl::uint16_t, Index>());
    CHECK(test<etl::uint32_t, Index>());
    CHECK(test<etl::uint64_t, Index>());

    CHECK(test<etl::int8_t, Index>());
    CHECK(test<etl::int16_t, Index>());
    CHECK(test<etl::int32_t, Index>());
    CHECK(test<etl::int64_t, Index>());

    CHECK(test<float, Index>());
    CHECK(test<double, Index>());

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
