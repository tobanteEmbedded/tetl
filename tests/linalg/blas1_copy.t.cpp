// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_copy_real() -> bool
{
    {
        // 1D static
        auto inData  = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4>{};

        auto in  = etl::mdspan<T const, etl::extents<IndexType, 4>>{inData.data()};
        auto out = etl::mdspan<T, etl::extents<IndexType, 4>>{outData.data()};

        etl::linalg::copy(in, out);
        CHECK(out(0) == in(0));
        CHECK(out(1) == in(1));
        CHECK(out(2) == in(2));
        CHECK(out(3) == in(3));
    }

    {
        // 1D dynamic
        auto inData  = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4>{};

        auto in  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{inData.data(), 4};
        auto out = etl::mdspan<T, etl::dextents<IndexType, 1>>{outData.data(), 4};

        etl::linalg::copy(in, out);
        CHECK(out(0) == in(0));
        CHECK(out(1) == in(1));
        CHECK(out(2) == in(2));
        CHECK(out(3) == in(3));
    }

    {
        // 2D static
        auto inData  = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4>{};

        auto in  = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{inData.data()};
        auto out = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{outData.data()};

        etl::linalg::copy(in, out);
        CHECK(out(0, 0) == in(0, 0));
        CHECK(out(0, 1) == in(0, 1));
        CHECK(out(1, 0) == in(1, 0));
        CHECK(out(1, 1) == in(1, 1));
    }

    {
        // 2D dynamic
        auto inData  = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4>{};

        auto in  = etl::mdspan<T const, etl::dextents<IndexType, 2>>{inData.data(), 2, 2};
        auto out = etl::mdspan<T, etl::dextents<IndexType, 2>>{outData.data(), 2, 2};

        etl::linalg::copy(in, out);
        CHECK(out(0, 0) == in(0, 0));
        CHECK(out(0, 1) == in(0, 1));
        CHECK(out(1, 0) == in(1, 0));
        CHECK(out(1, 1) == in(1, 1));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_copy_real<unsigned char, IndexType>());
    CHECK(test_linalg_copy_real<unsigned short, IndexType>());
    CHECK(test_linalg_copy_real<unsigned int, IndexType>());
    CHECK(test_linalg_copy_real<unsigned long, IndexType>());
    CHECK(test_linalg_copy_real<unsigned long long, IndexType>());

    CHECK(test_linalg_copy_real<signed char, IndexType>());
    CHECK(test_linalg_copy_real<signed short, IndexType>());
    CHECK(test_linalg_copy_real<signed int, IndexType>());
    CHECK(test_linalg_copy_real<signed long, IndexType>());
    CHECK(test_linalg_copy_real<signed long long, IndexType>());

    CHECK(test_linalg_copy_real<float, IndexType>());
    CHECK(test_linalg_copy_real<double, IndexType>());

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
