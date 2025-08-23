// SPDX-License-Identifier: BSL-1.0

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
[[nodiscard]] static constexpr auto test_linalg_vector_idx_abs_max_real() -> bool
{
    auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
    {
        // static extents
        auto const vec  = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};
        using size_type = typename decltype(vec)::size_type;

        CHECK(etl::linalg::idx_abs_max(vec) == size_type(3));
        CHECK(etl::linalg::idx_abs_max(etl::linalg::scaled(T(2), vec)) == size_type(3));
    }

    {
        // dynamic extents
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        using size_type = typename decltype(vec)::size_type;

        CHECK(etl::linalg::idx_abs_max(vec) == size_type(3));
        CHECK(etl::linalg::idx_abs_max(etl::linalg::scaled(T(4), vec)) == size_type(3));
    }

    if constexpr (etl::signed_integral<T>) {
        auto const negative = etl::array<T, 4>{T(0), T(-1), T(-2), T(3)};
        auto const vec      = etl::mdspan<T const, etl::dextents<IndexType, 1>>{negative.data(), 4};
        using size_type     = typename decltype(vec)::size_type;

        CHECK(etl::linalg::idx_abs_max(vec) == size_type(3));
        CHECK(etl::linalg::idx_abs_max(etl::linalg::scaled(T(2), vec)) == size_type(3));
    }

    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_idx_abs_max_complex() -> bool
{
    using complex_t = etl::complex<T>;

    auto const data = etl::array{
        complex_t(T(0), T(-0)),
        complex_t(T(3), T(-3)),
        complex_t(T(2), T(-2)),
        complex_t(T(1), T(-1)),
    };

    {
        // static extents
        auto const vec  = etl::mdspan<complex_t const, etl::extents<IndexType, 4>>{data.data()};
        using size_type = typename decltype(vec)::size_type;

        CHECK(etl::linalg::idx_abs_max(vec) == size_type(1));
        CHECK(etl::linalg::idx_abs_max(etl::linalg::scaled(T(2), vec)) == size_type(1));
    }

    {
        // dynamic extents
        auto const vec  = etl::mdspan<complex_t const, etl::dextents<IndexType, 1>>{data.data(), 4};
        using size_type = typename decltype(vec)::size_type;

        CHECK(etl::linalg::idx_abs_max(vec) == size_type(1));
        CHECK(etl::linalg::idx_abs_max(etl::linalg::scaled(T(4), vec)) == size_type(1));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_vector_idx_abs_max_real<unsigned char, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<unsigned short, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<unsigned int, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<unsigned long, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<unsigned long long, IndexType>());

    CHECK(test_linalg_vector_idx_abs_max_real<signed char, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<signed short, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<signed int, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<signed long, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<signed long long, IndexType>());

    CHECK(test_linalg_vector_idx_abs_max_real<float, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_real<double, IndexType>());

    CHECK(test_linalg_vector_idx_abs_max_complex<float, IndexType>());
    CHECK(test_linalg_vector_idx_abs_max_complex<double, IndexType>());

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
