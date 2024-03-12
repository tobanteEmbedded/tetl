// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_abs_sum_integer() -> bool
{
    {
        // static extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};
        assert(etl::linalg::vector_abs_sum(vec) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        assert(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    {
        // dynamic extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        assert(etl::linalg::vector_abs_sum(vec) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        assert(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(4), vec), T(0)) == T(24));
    }

    if constexpr (etl::signed_integral<T>) {
        auto const data = etl::array<T, 4>{T(0), T(-1), T(-2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        assert(etl::linalg::vector_abs_sum(vec) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        assert(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
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
        assert(etl::linalg::vector_abs_sum(vec) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        assert(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    {
        // dynamic extents
        auto const data = etl::array<T, 4>{T(0), T(1), T(2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        assert(etl::linalg::vector_abs_sum(vec) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        assert(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
    }

    {
        // negative
        auto const data = etl::array<T, 4>{T(0), T(-1), T(-2), T(3)};
        auto const vec  = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        assert(etl::linalg::vector_abs_sum(vec) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(6));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(7));
        assert(etl::linalg::vector_abs_sum(etl::linalg::scaled(T(2), vec), T(0)) == T(12));
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
        assert(etl::linalg::vector_abs_sum(vec) == T(12));
        assert(etl::linalg::vector_abs_sum(vec, T(0)) == T(12));
        assert(etl::linalg::vector_abs_sum(vec, T(1)) == T(13));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_vector_abs_sum_integer<unsigned char, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<unsigned short, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<unsigned int, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<unsigned long, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<unsigned long long, IndexType>());

    // assert(test_linalg_vector_abs_sum_integer<signed char, IndexType>());
    // assert(test_linalg_vector_abs_sum_integer<signed short, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<signed int, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<signed long, IndexType>());
    assert(test_linalg_vector_abs_sum_integer<signed long long, IndexType>());

    assert(test_linalg_vector_abs_sum_floats<float, IndexType>());
    assert(test_linalg_vector_abs_sum_floats<double, IndexType>());

    assert(test_linalg_vector_abs_sum_complex<float, IndexType>());
    assert(test_linalg_vector_abs_sum_complex<double, IndexType>());

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
    assert(test_all());
    static_assert(test_all());
    return EXIT_SUCCESS;
}
