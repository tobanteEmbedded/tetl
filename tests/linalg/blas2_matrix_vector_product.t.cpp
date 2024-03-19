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
        auto const matData = etl::array<T, 4>{T(0), T(0), T(0), T(0)};
        auto const vecData = etl::array<T, 2>{T(0), T(0)};
        auto outData       = etl::array<T, 2>{T(0), T(0)};

        auto mat = etl::mdspan<T const, etl::extents<int, 2, 2>>(matData.data());
        auto vec = etl::mdspan<T const, etl::extents<int, 2>>(vecData.data());
        auto out = etl::mdspan<T, etl::extents<int, 2>>(outData.data());

        etl::linalg::matrix_vector_product(mat, vec, out);
        CHECK(out(0) == T(0));
        CHECK(out(1) == T(0));

        etl::linalg::matrix_vector_product(mat, etl::linalg::scaled(T(2), vec), out);
        CHECK(out(0) == T(0));
        CHECK(out(1) == T(0));

        etl::linalg::matrix_vector_product(etl::linalg::scaled(T(2), mat), vec, out);
        CHECK(out(0) == T(0));
        CHECK(out(1) == T(0));
    }

    {
        // ones
        auto const matData = etl::array<T, 4>{T(1), T(1), T(1), T(1)};
        auto const vecData = etl::array<T, 2>{T(1), T(1)};
        auto outData       = etl::array<T, 2>{T(0), T(0)};

        auto mat = etl::mdspan<T const, etl::extents<int, 2, 2>>(matData.data());
        auto vec = etl::mdspan<T const, etl::extents<int, 2>>(vecData.data());
        auto out = etl::mdspan<T, etl::extents<int, 2>>(outData.data());

        etl::linalg::matrix_vector_product(mat, vec, out);
        CHECK(out(0) == T(2));
        CHECK(out(1) == T(2));

        etl::linalg::matrix_vector_product(mat, etl::linalg::scaled(T(2), vec), out);
        CHECK(out(0) == T(4));
        CHECK(out(1) == T(4));

        etl::linalg::matrix_vector_product(etl::linalg::scaled(T(2), mat), vec, out);
        CHECK(out(0) == T(4));
        CHECK(out(1) == T(4));
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_linalg_matrix_vector_product<unsigned char>());
    CHECK(test_linalg_matrix_vector_product<unsigned short>());
    CHECK(test_linalg_matrix_vector_product<unsigned int>());
    CHECK(test_linalg_matrix_vector_product<unsigned long>());
    CHECK(test_linalg_matrix_vector_product<unsigned long long>());

    CHECK(test_linalg_matrix_vector_product<signed char>());
    CHECK(test_linalg_matrix_vector_product<signed short>());
    CHECK(test_linalg_matrix_vector_product<signed int>());
    CHECK(test_linalg_matrix_vector_product<signed long>());
    CHECK(test_linalg_matrix_vector_product<signed long long>());

    CHECK(test_linalg_matrix_vector_product<float>());
    CHECK(test_linalg_matrix_vector_product<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
