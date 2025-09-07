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

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_two_norm_real() -> bool
{
    auto const data = etl::array<T, 4>{T(2), T(2), T(2), T(2)};
    {
        // static extents
        auto const vec = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};
        CHECK(etl::linalg::vector_two_norm(vec) == T(4));
        CHECK(etl::linalg::vector_two_norm(etl::linalg::scaled(T(2), vec)) == T(8));

        CHECK(etl::linalg::vector_two_norm(vec, T(0)) == T(4));
        CHECK(etl::linalg::vector_two_norm(etl::linalg::scaled(T(2), vec), T(0)) == T(8));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_vector_two_norm_real<float, IndexType>());
    CHECK(test_linalg_vector_two_norm_real<double, IndexType>());

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
