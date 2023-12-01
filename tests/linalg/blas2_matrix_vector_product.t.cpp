// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/cassert.hpp>
#include <etl/complex.hpp>

#include "testing/testing.hpp"

template <typename T>
[[nodiscard]] static constexpr auto test_linalg_matrix_vector_product() -> bool
{
    {
        // zeros
        auto const matData = etl::array<T, 4> {T(0), T(0), T(0), T(0)};
        auto const vecData = etl::array<T, 2> {T(0), T(0)};
        auto outData       = etl::array<T, 2> {T(0), T(0)};

        auto mat = etl::mdspan<T const, etl::extents<int, 2, 2>>(matData.data());
        auto vec = etl::mdspan<T const, etl::extents<int, 2>>(vecData.data());
        auto out = etl::mdspan<T, etl::extents<int, 2>>(outData.data());

        etl::linalg::matrix_vector_product(mat, vec, out);
        assert(out(0) == T(0));
        assert(out(1) == T(0));

        etl::linalg::matrix_vector_product(mat, etl::linalg::scaled(T(2), vec), out);
        assert(out(0) == T(0));
        assert(out(1) == T(0));

        etl::linalg::matrix_vector_product(etl::linalg::scaled(T(2), mat), vec, out);
        assert(out(0) == T(0));
        assert(out(1) == T(0));
    }

    {
        // ones
        auto const matData = etl::array<T, 4> {T(1), T(1), T(1), T(1)};
        auto const vecData = etl::array<T, 2> {T(1), T(1)};
        auto outData       = etl::array<T, 2> {T(0), T(0)};

        auto mat = etl::mdspan<T const, etl::extents<int, 2, 2>>(matData.data());
        auto vec = etl::mdspan<T const, etl::extents<int, 2>>(vecData.data());
        auto out = etl::mdspan<T, etl::extents<int, 2>>(outData.data());

        etl::linalg::matrix_vector_product(mat, vec, out);
        assert(out(0) == T(2));
        assert(out(1) == T(2));

        etl::linalg::matrix_vector_product(mat, etl::linalg::scaled(T(2), vec), out);
        assert(out(0) == T(4));
        assert(out(1) == T(4));

        etl::linalg::matrix_vector_product(etl::linalg::scaled(T(2), mat), vec, out);
        assert(out(0) == T(4));
        assert(out(1) == T(4));
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    assert(test_linalg_matrix_vector_product<unsigned char>());
    assert(test_linalg_matrix_vector_product<unsigned short>());
    assert(test_linalg_matrix_vector_product<unsigned int>());
    assert(test_linalg_matrix_vector_product<unsigned long>());
    assert(test_linalg_matrix_vector_product<unsigned long long>());

    assert(test_linalg_matrix_vector_product<signed char>());
    assert(test_linalg_matrix_vector_product<signed short>());
    assert(test_linalg_matrix_vector_product<signed int>());
    assert(test_linalg_matrix_vector_product<signed long>());
    assert(test_linalg_matrix_vector_product<signed long long>());

    assert(test_linalg_matrix_vector_product<float>());
    assert(test_linalg_matrix_vector_product<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
