// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.complex;
import etl.concepts;
import etl.linalg;
import etl.mdspan;
#else
    #include <etl/array.hpp>
    #include <etl/complex.hpp>
    #include <etl/concepts.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_abs_sum_integer() -> bool
{
    {
        // static extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        CHECK(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    {
        // dynamic extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        CHECK(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(4), vec), T(0)) == T(24));
    }

    if constexpr (etl::signed_integral<T>) {
        auto const data = etl::array<T, 4>{T(0), T(-1), T(-2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        CHECK(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }
    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_abs_sum_floats() -> bool
{
    {
        // static extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        CHECK(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    {
        // dynamic extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        CHECK(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    {
        // negative
        auto const data = etl::array<T, 4>{T(0), T(-1), T(-2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        CHECK(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_abs_sum_complex() -> bool
{
    using complex_t = etl::complex<T>;

    {
        // static extents
        auto const data = etl::array{
            complex_t(T(0), T(0)),
            complex_t(T(1), T(1)),
            complex_t(T(2), T(2)),
            complex_t(T(3), T(3)),
        };
        auto const vec = etl::mdspan<complex_t const, etl::extents<IndexType, 4>>{data.data()};
        CHECK(etl::linalg::vector_abs_sum(vec) == T(12));
        CHECK(etl::linalg::vector_abs_sum(vec, T(0)) == T(12));
        CHECK(etl::linalg::vector_abs_sum(vec, T(1)) == T(13));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_vector_abs_sum_integer<unsigned char, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<unsigned short, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<unsigned int, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<unsigned long, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<unsigned long long, IndexType>());

    // CHECK(test_linalg_vector_abs_sum_integer<signed char, IndexType>());
    // CHECK(test_linalg_vector_abs_sum_integer<signed short, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<signed int, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<signed long, IndexType>());
    CHECK(test_linalg_vector_abs_sum_integer<signed long long, IndexType>());

    CHECK(test_linalg_vector_abs_sum_floats<float, IndexType>());
    CHECK(test_linalg_vector_abs_sum_floats<double, IndexType>());

    CHECK(test_linalg_vector_abs_sum_complex<float, IndexType>());
    CHECK(test_linalg_vector_abs_sum_complex<double, IndexType>());

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
