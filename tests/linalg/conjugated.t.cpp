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
[[nodiscard]] static constexpr auto test_linalg_conjugated_real() -> bool
{
    auto const data = etl::array<T, 4>{T(2), T(2), T(2), T(2)};

    {
        // 1D static extents
        auto const vec = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};

        auto const conjugated = etl::linalg::conjugated(vec);
        CHECK(conjugated(0) == data[0]);
        CHECK(conjugated(1) == data[1]);
        CHECK(conjugated(2) == data[2]);
        CHECK(conjugated(3) == data[3]);

        auto const scaledConjugated = etl::linalg::conjugated(etl::linalg::scaled(T(2), vec));
        CHECK(scaledConjugated(0) == data[0] * T(2));
        CHECK(scaledConjugated(1) == data[1] * T(2));
        CHECK(scaledConjugated(2) == data[2] * T(2));
        CHECK(scaledConjugated(3) == data[3] * T(2));
    }

    {
        // 1D dynamic extents
        auto const vec        = etl::mdspan<T const, etl::dextents<IndexType, 1>>{data.data(), 4};
        auto const conjugated = etl::linalg::conjugated(vec);
        CHECK(conjugated(0) == data[0]);
        CHECK(conjugated(1) == data[1]);
        CHECK(conjugated(2) == data[2]);
        CHECK(conjugated(3) == data[3]);

        auto const scaledConjugated = etl::linalg::conjugated(etl::linalg::scaled(T(2), vec));
        CHECK(scaledConjugated(0) == data[0] * T(2));
        CHECK(scaledConjugated(1) == data[1] * T(2));
        CHECK(scaledConjugated(2) == data[2] * T(2));
        CHECK(scaledConjugated(3) == data[3] * T(2));
    }

    {
        // 2D static extents
        auto const vec        = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{data.data()};
        auto const conjugated = etl::linalg::conjugated(vec);
        CHECK(conjugated(0, 0) == data[0]);
        CHECK(conjugated(0, 1) == data[1]);
        CHECK(conjugated(1, 0) == data[2]);
        CHECK(conjugated(1, 1) == data[3]);

        auto const scaledConjugated = etl::linalg::conjugated(etl::linalg::scaled(T(2), vec));
        CHECK(scaledConjugated(0, 0) == data[0] * T(2));
        CHECK(scaledConjugated(0, 1) == data[1] * T(2));
        CHECK(scaledConjugated(1, 0) == data[2] * T(2));
        CHECK(scaledConjugated(1, 1) == data[3] * T(2));
    }

    return true;
}

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_conjugated_complex() -> bool
{
    auto const data = etl::array{
        etl::complex{T(0), T(0)},
        etl::complex{T(1), T(1)},
        etl::complex{T(2), T(2)},
        etl::complex{T(3), T(3)},
    };

    {
        // 1D static extents
        auto const vec              = etl::mdspan<etl::complex<T> const, etl::extents<IndexType, 4>>{data.data()};
        auto const conjugated       = etl::linalg::conjugated(vec);
        auto const doubleConjugated = etl::linalg::conjugated(conjugated);

        CHECK(etl::complex<T>(conjugated(0)) == etl::conj(data[0]));
        CHECK(etl::complex<T>(conjugated(1)) == etl::conj(data[1]));
        CHECK(etl::complex<T>(conjugated(2)) == etl::conj(data[2]));
        CHECK(etl::complex<T>(conjugated(3)) == etl::conj(data[3]));

        CHECK(doubleConjugated(0) == data[0]);
        CHECK(doubleConjugated(1) == data[1]);
        CHECK(doubleConjugated(2) == data[2]);
        CHECK(doubleConjugated(3) == data[3]);
    }

    {
        // 1D dynamic extents
        auto const vec              = etl::mdspan<etl::complex<T> const, etl::dextents<IndexType, 1>>{data.data(), 4};
        auto const conjugated       = etl::linalg::conjugated(vec);
        auto const doubleConjugated = etl::linalg::conjugated(conjugated);

        CHECK(etl::complex<T>(conjugated(0)) == etl::conj(data[0]));
        CHECK(etl::complex<T>(conjugated(1)) == etl::conj(data[1]));
        CHECK(etl::complex<T>(conjugated(2)) == etl::conj(data[2]));
        CHECK(etl::complex<T>(conjugated(3)) == etl::conj(data[3]));

        CHECK(doubleConjugated(0) == data[0]);
        CHECK(doubleConjugated(1) == data[1]);
        CHECK(doubleConjugated(2) == data[2]);
        CHECK(doubleConjugated(3) == data[3]);
    }

    {
        // 2D static extents
        auto const vec              = etl::mdspan<etl::complex<T> const, etl::extents<IndexType, 2, 2>>{data.data()};
        auto const conjugated       = etl::linalg::conjugated(vec);
        auto const doubleConjugated = etl::linalg::conjugated(conjugated);

        CHECK(etl::complex<T>(conjugated(0, 0)) == etl::conj(data[0]));
        CHECK(etl::complex<T>(conjugated(0, 1)) == etl::conj(data[1]));
        CHECK(etl::complex<T>(conjugated(1, 0)) == etl::conj(data[2]));
        CHECK(etl::complex<T>(conjugated(1, 1)) == etl::conj(data[3]));

        CHECK(doubleConjugated(0, 0) == data[0]);
        CHECK(doubleConjugated(0, 1) == data[1]);
        CHECK(doubleConjugated(1, 0) == data[2]);
        CHECK(doubleConjugated(1, 1) == data[3]);
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_linalg_conjugated_real<unsigned char, IndexType>());
    CHECK(test_linalg_conjugated_real<unsigned short, IndexType>());
    CHECK(test_linalg_conjugated_real<unsigned int, IndexType>());
    CHECK(test_linalg_conjugated_real<unsigned long, IndexType>());
    CHECK(test_linalg_conjugated_real<unsigned long long, IndexType>());

    CHECK(test_linalg_conjugated_real<signed char, IndexType>());
    CHECK(test_linalg_conjugated_real<signed short, IndexType>());
    CHECK(test_linalg_conjugated_real<signed int, IndexType>());
    CHECK(test_linalg_conjugated_real<signed long, IndexType>());
    CHECK(test_linalg_conjugated_real<signed long long, IndexType>());

    CHECK(test_linalg_conjugated_real<float, IndexType>());
    CHECK(test_linalg_conjugated_real<double, IndexType>());

    CHECK(test_linalg_conjugated_complex<float, IndexType>());
    CHECK(test_linalg_conjugated_complex<double, IndexType>());

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
