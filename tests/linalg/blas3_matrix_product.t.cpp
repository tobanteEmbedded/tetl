// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/complex.hpp>
    #include <etl/concepts.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T>
[[nodiscard]] static constexpr auto test_linalg_matrix_product() -> bool
{
    {
        // zeros
        auto const aBuf = etl::array<T, 4>{T(0), T(0), T(0), T(0)};
        auto const bBuf = etl::array<T, 4>{T(0), T(0), T(0), T(0)};
        auto cBuf       = etl::array<T, 4>{T(0), T(0), T(0), T(0)};

        auto const a = etl::mdspan<T const, etl::extents<int, 2, 2>>(aBuf.data());
        auto const b = etl::mdspan<T const, etl::extents<int, 2, 2>>(bBuf.data());
        auto const c = etl::mdspan<T, etl::extents<int, 2, 2>>(cBuf.data());

        etl::linalg::matrix_product(a, b, c);
        CHECK(c(0, 0) == T(0));
        CHECK(c(0, 1) == T(0));
        CHECK(c(1, 0) == T(0));
        CHECK(c(1, 1) == T(0));

        etl::linalg::matrix_product(etl::linalg::scaled(T(2), a), b, c);
        CHECK(c(0, 0) == T(0));
        CHECK(c(0, 1) == T(0));
        CHECK(c(1, 0) == T(0));
        CHECK(c(1, 1) == T(0));

        etl::linalg::matrix_product(a, etl::linalg::scaled(T(2), b), c);
        CHECK(c(0, 0) == T(0));
        CHECK(c(0, 1) == T(0));
        CHECK(c(1, 0) == T(0));
        CHECK(c(1, 1) == T(0));
    }

    {
        // ones
        auto const aBuf = etl::array<T, 4>{T(1), T(1), T(1), T(1)};
        auto const bBuf = etl::array<T, 4>{T(1), T(1), T(1), T(1)};
        auto cBuf       = etl::array<T, 4>{T(0), T(0), T(0), T(0)};

        auto const a = etl::mdspan<T const, etl::extents<int, 2, 2>>(aBuf.data());
        auto const b = etl::mdspan<T const, etl::extents<int, 2, 2>>(bBuf.data());
        auto const c = etl::mdspan<T, etl::extents<int, 2, 2>>(cBuf.data());

        etl::linalg::matrix_product(a, b, c);
        CHECK(c(0, 0) == T(2));
        CHECK(c(0, 1) == T(2));
        CHECK(c(1, 0) == T(2));
        CHECK(c(1, 1) == T(2));

        etl::linalg::matrix_product(etl::linalg::scaled(T(2), a), b, c);
        CHECK(c(0, 0) == T(4));
        CHECK(c(0, 1) == T(4));
        CHECK(c(1, 0) == T(4));
        CHECK(c(1, 1) == T(4));

        etl::linalg::matrix_product(a, etl::linalg::scaled(T(2), b), c);
        CHECK(c(0, 0) == T(4));
        CHECK(c(0, 1) == T(4));
        CHECK(c(1, 0) == T(4));
        CHECK(c(1, 1) == T(4));
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_linalg_matrix_product<unsigned char>());
    CHECK(test_linalg_matrix_product<unsigned short>());
    CHECK(test_linalg_matrix_product<unsigned int>());
    CHECK(test_linalg_matrix_product<unsigned long>());
    CHECK(test_linalg_matrix_product<unsigned long long>());

    CHECK(test_linalg_matrix_product<signed char>());
    CHECK(test_linalg_matrix_product<signed short>());
    CHECK(test_linalg_matrix_product<signed int>());
    CHECK(test_linalg_matrix_product<signed long>());
    CHECK(test_linalg_matrix_product<signed long long>());

    CHECK(test_linalg_matrix_product<float>());
    CHECK(test_linalg_matrix_product<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
