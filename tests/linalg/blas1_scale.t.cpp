// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/complex.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_scale_real() -> bool
{
    {
        // 1D static extents
        auto data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto vec  = etl::mdspan<T, etl::extents<IndexType, 4>>{data.data()};
        CHECK(vec(0) == T(0));
        CHECK(vec(1) == T(1));
        CHECK(vec(2) == T(2));
        CHECK(vec(3) == T(3));

        etl::linalg::scale(T(2), vec);
        CHECK(vec(0) == T(0));
        CHECK(vec(1) == T(2));
        CHECK(vec(2) == T(4));
        CHECK(vec(3) == T(6));
    }

    {
        // 1D dynamic extents
        auto data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto vec  = etl::mdspan<T, etl::dextents<IndexType, 1>>{data.data(), data.size()};
        CHECK(vec(0) == T(0));
        CHECK(vec(1) == T(1));
        CHECK(vec(2) == T(2));
        CHECK(vec(3) == T(3));

        etl::linalg::scale(T(2), vec);
        CHECK(vec(0) == T(0));
        CHECK(vec(1) == T(2));
        CHECK(vec(2) == T(4));
        CHECK(vec(3) == T(6));
    }

    {
        // 2D static extents
        auto data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto vec  = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{data.data()};
        CHECK(vec(0, 0) == T(0));
        CHECK(vec(0, 1) == T(1));
        CHECK(vec(1, 0) == T(2));
        CHECK(vec(1, 1) == T(3));

        etl::linalg::scale(T(2), vec);
        CHECK(vec(0, 0) == T(0));
        CHECK(vec(0, 1) == T(2));
        CHECK(vec(1, 0) == T(4));
        CHECK(vec(1, 1) == T(6));
    }

    {
        // 2D dynamic extents
        auto data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto vec  = etl::mdspan<T, etl::dextents<IndexType, 2>>{data.data(), 2, 2};
        CHECK(vec(0, 0) == T(0));
        CHECK(vec(0, 1) == T(1));
        CHECK(vec(1, 0) == T(2));
        CHECK(vec(1, 1) == T(3));

        etl::linalg::scale(T(2), vec);
        CHECK(vec(0, 0) == T(0));
        CHECK(vec(0, 1) == T(2));
        CHECK(vec(1, 0) == T(4));
        CHECK(vec(1, 1) == T(6));
    }

    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_scale_complex() -> bool
{
    using complex_t = etl::complex<T>;

    {
        // 1D static extents
        auto data = etl::array<complex_t, 4>{
            complex_t{T(0), T(0)},
            complex_t{T(1), T(1)},
            complex_t{T(2), T(2)},
            complex_t{T(3), T(3)},
        };
        auto const original = data;

        auto vec = etl::mdspan<complex_t, etl::extents<IndexType, 4>>{data.data()};
        CHECK(vec(0) == original[0]);
        CHECK(vec(1) == original[1]);
        CHECK(vec(2) == original[2]);
        CHECK(vec(3) == original[3]);

        etl::linalg::scale(T(2), vec);
        CHECK(vec(0) == original[0] * T(2));
        CHECK(vec(1) == original[1] * T(2));
        CHECK(vec(2) == original[2] * T(2));
        CHECK(vec(3) == original[3] * T(2));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_scale_real<unsigned char, IndexType>());
    CHECK(test_linalg_scale_real<unsigned short, IndexType>());
    CHECK(test_linalg_scale_real<unsigned int, IndexType>());
    CHECK(test_linalg_scale_real<unsigned long, IndexType>());
    CHECK(test_linalg_scale_real<unsigned long long, IndexType>());

    CHECK(test_linalg_scale_real<signed char, IndexType>());
    CHECK(test_linalg_scale_real<signed short, IndexType>());
    CHECK(test_linalg_scale_real<signed int, IndexType>());
    CHECK(test_linalg_scale_real<signed long, IndexType>());
    CHECK(test_linalg_scale_real<signed long long, IndexType>());

    CHECK(test_linalg_scale_real<float, IndexType>());
    CHECK(test_linalg_scale_real<double, IndexType>());

    CHECK(test_linalg_scale_complex<float, IndexType>());
    CHECK(test_linalg_scale_complex<double, IndexType>());

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
