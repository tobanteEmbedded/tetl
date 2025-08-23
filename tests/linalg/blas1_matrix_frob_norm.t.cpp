// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_matrix_frob_norm() -> bool
{
    auto const zeros = etl::array<T, 4>{};
    auto const ones  = etl::array<T, 4>{T(1), T(1), T(1), T(1)};

    {
        // 2D static
        auto const matZeros = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{zeros.data()};
        auto const matOnes  = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{ones.data()};
        CHECK(etl::linalg::matrix_frob_norm(matZeros) == T(0));
        CHECK(etl::linalg::matrix_frob_norm(matOnes) == T(2));
    }

    {
        // 2D dynamic
        auto const matZeros = etl::mdspan<T const, etl::dextents<IndexType, 2>>{zeros.data(), 2, 2};
        auto const matOnes  = etl::mdspan<T const, etl::dextents<IndexType, 2>>{ones.data(), 2, 2};
        CHECK(etl::linalg::matrix_frob_norm(matZeros) == T(0));
        CHECK(etl::linalg::matrix_frob_norm(matOnes) == T(2));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_matrix_frob_norm<unsigned char, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<unsigned short, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<unsigned int, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<unsigned long, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<unsigned long long, IndexType>());

    CHECK(test_linalg_matrix_frob_norm<signed char, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<signed short, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<signed int, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<signed long, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<signed long long, IndexType>());

    CHECK(test_linalg_matrix_frob_norm<float, IndexType>());
    CHECK(test_linalg_matrix_frob_norm<double, IndexType>());

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_index_type<signed char>());
    CHECK(test_index_type<signed short>());
    CHECK(test_index_type<signed int>());
    CHECK(test_index_type<signed long>());
    CHECK(test_index_type<signed long long>());

    CHECK(test_index_type<unsigned char>());
    CHECK(test_index_type<unsigned short>());
    CHECK(test_index_type<unsigned int>());
    CHECK(test_index_type<unsigned long>());
    CHECK(test_index_type<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return EXIT_SUCCESS;
}
