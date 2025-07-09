// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.linalg;
import etl.mdspan;
#else
    #include <etl/array.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

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
        CHECK(lhs(0) == T(1));
        CHECK(lhs(1) == T(2));
        CHECK(lhs(2) == T(3));
        CHECK(lhs(3) == T(4));

        CHECK(rhs(0) == T(0));
        CHECK(rhs(1) == T(0));
        CHECK(rhs(2) == T(0));
        CHECK(rhs(3) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0) == T(0));
        CHECK(lhs(1) == T(0));
        CHECK(lhs(2) == T(0));
        CHECK(lhs(3) == T(0));

        CHECK(rhs(0) == T(1));
        CHECK(rhs(1) == T(2));
        CHECK(rhs(2) == T(3));
        CHECK(rhs(3) == T(4));
    }

    {
        // 1D dynamic
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::dextents<IndexType, 1>>{lhsData.data(), 4};
        auto rhs = etl::mdspan<T, etl::dextents<IndexType, 1>>{rhsData.data(), 4};

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0) == T(1));
        CHECK(lhs(1) == T(2));
        CHECK(lhs(2) == T(3));
        CHECK(lhs(3) == T(4));

        CHECK(rhs(0) == T(0));
        CHECK(rhs(1) == T(0));
        CHECK(rhs(2) == T(0));
        CHECK(rhs(3) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0) == T(0));
        CHECK(lhs(1) == T(0));
        CHECK(lhs(2) == T(0));
        CHECK(lhs(3) == T(0));

        CHECK(rhs(0) == T(1));
        CHECK(rhs(1) == T(2));
        CHECK(rhs(2) == T(3));
        CHECK(rhs(3) == T(4));
    }

    {
        // 2D static
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{lhsData.data()};
        auto rhs = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{rhsData.data()};

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0, 0) == T(1));
        CHECK(lhs(0, 1) == T(2));
        CHECK(lhs(1, 0) == T(3));
        CHECK(lhs(1, 1) == T(4));

        CHECK(rhs(0, 0) == T(0));
        CHECK(rhs(0, 1) == T(0));
        CHECK(rhs(1, 0) == T(0));
        CHECK(rhs(1, 1) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0, 0) == T(0));
        CHECK(lhs(0, 1) == T(0));
        CHECK(lhs(1, 0) == T(0));
        CHECK(lhs(1, 1) == T(0));

        CHECK(rhs(0, 0) == T(1));
        CHECK(rhs(0, 1) == T(2));
        CHECK(rhs(1, 0) == T(3));
        CHECK(rhs(1, 1) == T(4));
    }

    {
        // 2D dynamic
        auto lhsData = zeroData;
        auto rhsData = otherData;

        auto lhs = etl::mdspan<T, etl::dextents<IndexType, 2>>{lhsData.data(), 2, 2};
        auto rhs = etl::mdspan<T, etl::dextents<IndexType, 2>>{rhsData.data(), 2, 2};

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0, 0) == T(1));
        CHECK(lhs(0, 1) == T(2));
        CHECK(lhs(1, 0) == T(3));
        CHECK(lhs(1, 1) == T(4));

        CHECK(rhs(0, 0) == T(0));
        CHECK(rhs(0, 1) == T(0));
        CHECK(rhs(1, 0) == T(0));
        CHECK(rhs(1, 1) == T(0));

        etl::linalg::swap_elements(lhs, rhs);
        CHECK(lhs(0, 0) == T(0));
        CHECK(lhs(0, 1) == T(0));
        CHECK(lhs(1, 0) == T(0));
        CHECK(lhs(1, 1) == T(0));

        CHECK(rhs(0, 0) == T(1));
        CHECK(rhs(0, 1) == T(2));
        CHECK(rhs(1, 0) == T(3));
        CHECK(rhs(1, 1) == T(4));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_swap_elements_real<unsigned char, IndexType>());
    CHECK(test_linalg_swap_elements_real<unsigned short, IndexType>());
    CHECK(test_linalg_swap_elements_real<unsigned int, IndexType>());
    CHECK(test_linalg_swap_elements_real<unsigned long, IndexType>());
    CHECK(test_linalg_swap_elements_real<unsigned long long, IndexType>());

    CHECK(test_linalg_swap_elements_real<signed char, IndexType>());
    CHECK(test_linalg_swap_elements_real<signed short, IndexType>());
    CHECK(test_linalg_swap_elements_real<signed int, IndexType>());
    CHECK(test_linalg_swap_elements_real<signed long, IndexType>());
    CHECK(test_linalg_swap_elements_real<signed long long, IndexType>());

    CHECK(test_linalg_swap_elements_real<float, IndexType>());
    CHECK(test_linalg_swap_elements_real<double, IndexType>());

    return true;
}
