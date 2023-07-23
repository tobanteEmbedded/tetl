// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_conjugated_real() -> bool
{
    auto const data = etl::array<T, 4> { T(2), T(2), T(2), T(2) };

    {
        // 1D static extents
        auto const vec        = etl::mdspan<T const, etl::extents<IndexType, 4>> { data.data() };
        auto const conjugated = etl::linalg::conjugated(vec);
        assert(conjugated(0) == data[0]);
        assert(conjugated(1) == data[1]);
        assert(conjugated(2) == data[2]);
        assert(conjugated(3) == data[3]);
    }

    {
        // 1D dynamic extents
        auto const vec        = etl::mdspan<T const, etl::dextents<IndexType, 1>> { data.data(), 4 };
        auto const conjugated = etl::linalg::conjugated(vec);
        assert(conjugated(0) == data[0]);
        assert(conjugated(1) == data[1]);
        assert(conjugated(2) == data[2]);
        assert(conjugated(3) == data[3]);
    }

    {
        // 2D static extents
        auto const vec        = etl::mdspan<T const, etl::extents<IndexType, 2, 2>> { data.data() };
        auto const conjugated = etl::linalg::conjugated(vec);
        assert(conjugated(0, 0) == data[0]);
        assert(conjugated(0, 1) == data[1]);
        assert(conjugated(1, 0) == data[2]);
        assert(conjugated(1, 1) == data[3]);
    }

    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_conjugated_complex() -> bool
{
    auto const data = etl::array {
        etl::complex { T(0), T(0) },
        etl::complex { T(1), T(1) },
        etl::complex { T(2), T(2) },
        etl::complex { T(3), T(3) },
    };

    {
        // 1D static extents
        auto const vec               = etl::mdspan<etl::complex<T> const, etl::extents<IndexType, 4>> { data.data() };
        auto const conjugated        = etl::linalg::conjugated(vec);
        auto const double_conjugated = etl::linalg::conjugated(conjugated);

        assert(etl::complex<T>(conjugated(0)) == etl::conj(data[0]));
        assert(etl::complex<T>(conjugated(1)) == etl::conj(data[1]));
        assert(etl::complex<T>(conjugated(2)) == etl::conj(data[2]));
        assert(etl::complex<T>(conjugated(3)) == etl::conj(data[3]));

        assert(double_conjugated(0) == data[0]);
        assert(double_conjugated(1) == data[1]);
        assert(double_conjugated(2) == data[2]);
        assert(double_conjugated(3) == data[3]);
    }

    {
        // 1D dynamic extents
        auto const vec        = etl::mdspan<etl::complex<T> const, etl::dextents<IndexType, 1>> { data.data(), 4 };
        auto const conjugated = etl::linalg::conjugated(vec);
        auto const double_conjugated = etl::linalg::conjugated(conjugated);

        assert(etl::complex<T>(conjugated(0)) == etl::conj(data[0]));
        assert(etl::complex<T>(conjugated(1)) == etl::conj(data[1]));
        assert(etl::complex<T>(conjugated(2)) == etl::conj(data[2]));
        assert(etl::complex<T>(conjugated(3)) == etl::conj(data[3]));

        assert(double_conjugated(0) == data[0]);
        assert(double_conjugated(1) == data[1]);
        assert(double_conjugated(2) == data[2]);
        assert(double_conjugated(3) == data[3]);
    }

    {
        // 2D static extents
        auto const vec        = etl::mdspan<etl::complex<T> const, etl::extents<IndexType, 2, 2>> { data.data() };
        auto const conjugated = etl::linalg::conjugated(vec);
        auto const double_conjugated = etl::linalg::conjugated(conjugated);

        assert(etl::complex<T>(conjugated(0, 0)) == etl::conj(data[0]));
        assert(etl::complex<T>(conjugated(0, 1)) == etl::conj(data[1]));
        assert(etl::complex<T>(conjugated(1, 0)) == etl::conj(data[2]));
        assert(etl::complex<T>(conjugated(1, 1)) == etl::conj(data[3]));

        assert(double_conjugated(0, 0) == data[0]);
        assert(double_conjugated(0, 1) == data[1]);
        assert(double_conjugated(1, 0) == data[2]);
        assert(double_conjugated(1, 1) == data[3]);
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_conjugated_real<unsigned char, IndexType>());
    assert(test_linalg_conjugated_real<unsigned short, IndexType>());
    assert(test_linalg_conjugated_real<unsigned int, IndexType>());
    assert(test_linalg_conjugated_real<unsigned long, IndexType>());
    assert(test_linalg_conjugated_real<unsigned long long, IndexType>());

    assert(test_linalg_conjugated_real<signed char, IndexType>());
    assert(test_linalg_conjugated_real<signed short, IndexType>());
    assert(test_linalg_conjugated_real<signed int, IndexType>());
    assert(test_linalg_conjugated_real<signed long, IndexType>());
    assert(test_linalg_conjugated_real<signed long long, IndexType>());

    assert(test_linalg_conjugated_real<float, IndexType>());
    assert(test_linalg_conjugated_real<double, IndexType>());

    assert(test_linalg_conjugated_complex<float, IndexType>());
    assert(test_linalg_conjugated_complex<double, IndexType>());

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
