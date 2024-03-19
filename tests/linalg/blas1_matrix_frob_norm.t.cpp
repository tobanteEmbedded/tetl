// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_matrix_frob_norm() -> bool
{
    auto const zeros = etl::array<T, 4>{};
    auto const ones  = etl::array<T, 4>{T(1), T(1), T(1), T(1)};

    {
        // 2D static
        auto const matZeros = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{zeros.data()};
        auto const matOnes  = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{ones.data()};
        assert(etl::linalg::matrix_frob_norm(matZeros) == T(0));
        assert(etl::linalg::matrix_frob_norm(matOnes) == T(2));
    }

    {
        // 2D dynamic
        auto const matZeros = etl::mdspan<T const, etl::dextents<IndexType, 2>>{zeros.data(), 2, 2};
        auto const matOnes  = etl::mdspan<T const, etl::dextents<IndexType, 2>>{ones.data(), 2, 2};
        assert(etl::linalg::matrix_frob_norm(matZeros) == T(0));
        assert(etl::linalg::matrix_frob_norm(matOnes) == T(2));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_matrix_frob_norm<unsigned char, IndexType>());
    assert(test_linalg_matrix_frob_norm<unsigned short, IndexType>());
    assert(test_linalg_matrix_frob_norm<unsigned int, IndexType>());
    assert(test_linalg_matrix_frob_norm<unsigned long, IndexType>());
    assert(test_linalg_matrix_frob_norm<unsigned long long, IndexType>());

    assert(test_linalg_matrix_frob_norm<signed char, IndexType>());
    assert(test_linalg_matrix_frob_norm<signed short, IndexType>());
    assert(test_linalg_matrix_frob_norm<signed int, IndexType>());
    assert(test_linalg_matrix_frob_norm<signed long, IndexType>());
    assert(test_linalg_matrix_frob_norm<signed long long, IndexType>());

    assert(test_linalg_matrix_frob_norm<float, IndexType>());
    assert(test_linalg_matrix_frob_norm<double, IndexType>());

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
    STATIC_CHECK(test_all());
    return EXIT_SUCCESS;
}
