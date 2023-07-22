// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_scale_real() -> bool
{
    {
        // 1D static extents
        auto data   = etl::array<T, 4> { T(0), T(1), T(2), T(3) };
        auto vec    = etl::mdspan<T, etl::extents<IndexType, 4>> { data.data() };
        auto scaled = etl::linalg::scaled(T(2), vec);

        assert(scaled(0) == T(0));
        assert(scaled(1) == T(2));
        assert(scaled(2) == T(4));
        assert(scaled(3) == T(6));
    }

    {
        // 1D dynamic extents
        auto data   = etl::array<T, 4> { T(0), T(1), T(2), T(3) };
        auto vec    = etl::mdspan<T, etl::dextents<IndexType, 1>> { data.data(), data.size() };
        auto scaled = etl::linalg::scaled(T(2), vec);

        assert(scaled(0) == T(0));
        assert(scaled(1) == T(2));
        assert(scaled(2) == T(4));
        assert(scaled(3) == T(6));
    }

    {
        // 2D static extents
        auto data   = etl::array<T, 4> { T(0), T(1), T(2), T(3) };
        auto vec    = etl::mdspan<T, etl::extents<IndexType, 2, 2>> { data.data() };
        auto scaled = etl::linalg::scaled(T(2), vec);

        assert(scaled(0, 0) == T(0));
        assert(scaled(0, 1) == T(2));
        assert(scaled(1, 0) == T(4));
        assert(scaled(1, 1) == T(6));
    }

    {
        // 2D dynamic extents
        auto data   = etl::array<T, 4> { T(0), T(1), T(2), T(3) };
        auto vec    = etl::mdspan<T, etl::dextents<IndexType, 2>> { data.data(), 2, 2 };
        auto scaled = etl::linalg::scaled(T(2), vec);

        assert(scaled(0, 0) == T(0));
        assert(scaled(0, 1) == T(2));
        assert(scaled(1, 0) == T(4));
        assert(scaled(1, 1) == T(6));
    }

    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_scale_complex() -> bool
{
    using complex_t = etl::complex<T>;

    {
        // 1D static extents
        auto const data = etl::array<complex_t, 4> {
            complex_t { T(0), T(0) },
            complex_t { T(1), T(1) },
            complex_t { T(2), T(2) },
            complex_t { T(3), T(3) },
        };

        auto vec    = etl::mdspan<complex_t const, etl::extents<IndexType, 4>> { data.data() };
        auto scaled = etl::linalg::scaled(T(2), vec);

        assert(complex_t(scaled(0)) == vec[0] * T(2));
        assert(complex_t(scaled(1)) == vec[1] * T(2));
        assert(complex_t(scaled(2)) == vec[2] * T(2));
        assert(complex_t(scaled(3)) == vec[3] * T(2));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_scale_real<unsigned char, IndexType>());
    assert(test_linalg_scale_real<unsigned short, IndexType>());
    assert(test_linalg_scale_real<unsigned int, IndexType>());
    assert(test_linalg_scale_real<unsigned long, IndexType>());
    assert(test_linalg_scale_real<unsigned long long, IndexType>());

    assert(test_linalg_scale_real<signed char, IndexType>());
    assert(test_linalg_scale_real<signed short, IndexType>());
    assert(test_linalg_scale_real<signed int, IndexType>());
    assert(test_linalg_scale_real<signed long, IndexType>());
    assert(test_linalg_scale_real<signed long long, IndexType>());

    assert(test_linalg_scale_real<float, IndexType>());
    assert(test_linalg_scale_real<double, IndexType>());

    // assert(test_linalg_scale_complex<float, IndexType>());
    // assert(test_linalg_scale_complex<double, IndexType>());

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
