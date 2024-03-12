// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_swap_elements_real() -> bool
{
    auto const zeroData  = etl::array<T, 4>{};
    auto const otherData = etl::array<T, 4>{T(1), T(2), T(3), T(4)};

    {
        // 1D static
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::extents<IndexType, 4>>{lhsData.data()};
        auto rhs = etl::mdspan<T, etl::extents<IndexType, 4>>{rhsData.data()};

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0) == T(1));
        assert(lhs(1) == T(2));
        assert(lhs(2) == T(3));
        assert(lhs(3) == T(4));

        assert(rhs(0) == T(0));
        assert(rhs(1) == T(0));
        assert(rhs(2) == T(0));
        assert(rhs(3) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0) == T(0));
        assert(lhs(1) == T(0));
        assert(lhs(2) == T(0));
        assert(lhs(3) == T(0));

        assert(rhs(0) == T(1));
        assert(rhs(1) == T(2));
        assert(rhs(2) == T(3));
        assert(rhs(3) == T(4));
    }

    {
        // 1D dynamic
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::dextents<IndexType, 1>>{lhsData.data(), 4};
        auto rhs = etl::mdspan<T, etl::dextents<IndexType, 1>>{rhsData.data(), 4};

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0) == T(1));
        assert(lhs(1) == T(2));
        assert(lhs(2) == T(3));
        assert(lhs(3) == T(4));

        assert(rhs(0) == T(0));
        assert(rhs(1) == T(0));
        assert(rhs(2) == T(0));
        assert(rhs(3) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0) == T(0));
        assert(lhs(1) == T(0));
        assert(lhs(2) == T(0));
        assert(lhs(3) == T(0));

        assert(rhs(0) == T(1));
        assert(rhs(1) == T(2));
        assert(rhs(2) == T(3));
        assert(rhs(3) == T(4));
    }

    {
        // 2D static
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{lhsData.data()};
        auto rhs = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{rhsData.data()};

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0, 0) == T(1));
        assert(lhs(0, 1) == T(2));
        assert(lhs(1, 0) == T(3));
        assert(lhs(1, 1) == T(4));

        assert(rhs(0, 0) == T(0));
        assert(rhs(0, 1) == T(0));
        assert(rhs(1, 0) == T(0));
        assert(rhs(1, 1) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0, 0) == T(0));
        assert(lhs(0, 1) == T(0));
        assert(lhs(1, 0) == T(0));
        assert(lhs(1, 1) == T(0));

        assert(rhs(0, 0) == T(1));
        assert(rhs(0, 1) == T(2));
        assert(rhs(1, 0) == T(3));
        assert(rhs(1, 1) == T(4));
    }

    {
        // 2D dynamic
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::dextents<IndexType, 2>>{lhsData.data(), 2, 2};
        auto rhs = etl::mdspan<T, etl::dextents<IndexType, 2>>{rhsData.data(), 2, 2};

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0, 0) == T(1));
        assert(lhs(0, 1) == T(2));
        assert(lhs(1, 0) == T(3));
        assert(lhs(1, 1) == T(4));

        assert(rhs(0, 0) == T(0));
        assert(rhs(0, 1) == T(0));
        assert(rhs(1, 0) == T(0));
        assert(rhs(1, 1) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        assert(lhs(0, 0) == T(0));
        assert(lhs(0, 1) == T(0));
        assert(lhs(1, 0) == T(0));
        assert(lhs(1, 1) == T(0));

        assert(rhs(0, 0) == T(1));
        assert(rhs(0, 1) == T(2));
        assert(rhs(1, 0) == T(3));
        assert(rhs(1, 1) == T(4));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_swap_elements_real<unsigned char, IndexType>());
    assert(test_linalg_swap_elements_real<unsigned short, IndexType>());
    assert(test_linalg_swap_elements_real<unsigned int, IndexType>());
    assert(test_linalg_swap_elements_real<unsigned long, IndexType>());
    assert(test_linalg_swap_elements_real<unsigned long long, IndexType>());

    assert(test_linalg_swap_elements_real<signed char, IndexType>());
    assert(test_linalg_swap_elements_real<signed short, IndexType>());
    assert(test_linalg_swap_elements_real<signed int, IndexType>());
    assert(test_linalg_swap_elements_real<signed long, IndexType>());
    assert(test_linalg_swap_elements_real<signed long long, IndexType>());

    assert(test_linalg_swap_elements_real<float, IndexType>());
    assert(test_linalg_swap_elements_real<double, IndexType>());

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    assert(test_index_type<signed char>());
    assert(test_index_type<signed short>());
    assert(test_index_type<signed int>());
    assert(test_index_type<signed long>());
    assert(test_index_type<signed long long>());

    assert(test_index_type<unsigned char>());
    assert(test_index_type<unsigned short>());
    assert(test_index_type<unsigned int>());
    assert(test_index_type<unsigned long>());
    assert(test_index_type<unsigned long long>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return EXIT_SUCCESS;
}
