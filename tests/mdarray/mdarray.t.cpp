// SPDX-License-Identifier: BSL-1.0

#include <etl/mdarray.hpp>

#include <etl/array.hpp>
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

        CHECK(matrix().size() == 6);
        CHECK_FALSE(matrix().empty());
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

        {
            typename array_matrix::mdspan_type view        = am;
            typename array_matrix::const_mdspan_type cview = etl::as_const(am);
            CHECK(view.extents() == am.extents());
            CHECK(cview.extents() == am.extents());
            CHECK(am(0, 0) == view(0, 0));
            CHECK(am(0, 0) == cview(0, 0));
        }

        {
            auto view  = am.to_mdspan();
            auto cview = etl::as_const(am).to_mdspan();
            CHECK(view.extents() == am.extents());
            CHECK(cview.extents() == am.extents());
            CHECK(am(0, 0) == view(0, 0));
            CHECK(am(0, 0) == cview(0, 0));
        }

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
[[nodiscard]] constexpr auto test_index() -> bool
{
    CHECK(test<unsigned char, Index>());
    CHECK(test<unsigned short, Index>());
    CHECK(test<unsigned int, Index>());
    CHECK(test<unsigned long, Index>());
    CHECK(test<unsigned long long, Index>());

    CHECK(test<signed char, Index>());
    CHECK(test<signed short, Index>());
    CHECK(test<signed int, Index>());
    CHECK(test<signed long, Index>());
    CHECK(test<signed long long, Index>());

    CHECK(test<char, Index>());
    CHECK(test<char8_t, Index>());
    CHECK(test<char16_t, Index>());
    CHECK(test<char32_t, Index>());

    CHECK(test<float, Index>());
    CHECK(test<double, Index>());
    CHECK(test<long double, Index>());

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_index<unsigned char>());
    CHECK(test_index<unsigned short>());
    CHECK(test_index<unsigned int>());
    CHECK(test_index<unsigned long>());
    CHECK(test_index<unsigned long long>());

    CHECK(test_index<signed char>());
    CHECK(test_index<signed short>());
    CHECK(test_index<signed int>());
    CHECK(test_index<signed long>());
    CHECK(test_index<signed long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
