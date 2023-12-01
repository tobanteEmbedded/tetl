// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_copy_real() -> bool
{
    {
        // 1D static
        auto inData  = etl::array<T, 4> {T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4> {};

        auto in  = etl::mdspan<T const, etl::extents<IndexType, 4>> {inData.data()};
        auto out = etl::mdspan<T, etl::extents<IndexType, 4>> {outData.data()};

        etl::linalg::copy(in, out);
        assert(out(0) == in(0));
        assert(out(1) == in(1));
        assert(out(2) == in(2));
        assert(out(3) == in(3));
    }

    {
        // 1D dynamic
        auto inData  = etl::array<T, 4> {T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4> {};

        auto in  = etl::mdspan<T const, etl::dextents<IndexType, 1>> {inData.data(), 4};
        auto out = etl::mdspan<T, etl::dextents<IndexType, 1>> {outData.data(), 4};

        etl::linalg::copy(in, out);
        assert(out(0) == in(0));
        assert(out(1) == in(1));
        assert(out(2) == in(2));
        assert(out(3) == in(3));
    }

    {
        // 2D static
        auto inData  = etl::array<T, 4> {T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4> {};

        auto in  = etl::mdspan<T const, etl::extents<IndexType, 2, 2>> {inData.data()};
        auto out = etl::mdspan<T, etl::extents<IndexType, 2, 2>> {outData.data()};

        etl::linalg::copy(in, out);
        assert(out(0, 0) == in(0, 0));
        assert(out(0, 1) == in(0, 1));
        assert(out(1, 0) == in(1, 0));
        assert(out(1, 1) == in(1, 1));
    }

    {
        // 2D dynamic
        auto inData  = etl::array<T, 4> {T(0), T(1), T(2), T(3)};
        auto outData = etl::array<T, 4> {};

        auto in  = etl::mdspan<T const, etl::dextents<IndexType, 2>> {inData.data(), 2, 2};
        auto out = etl::mdspan<T, etl::dextents<IndexType, 2>> {outData.data(), 2, 2};

        etl::linalg::copy(in, out);
        assert(out(0, 0) == in(0, 0));
        assert(out(0, 1) == in(0, 1));
        assert(out(1, 0) == in(1, 0));
        assert(out(1, 1) == in(1, 1));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_copy_real<unsigned char, IndexType>());
    assert(test_linalg_copy_real<unsigned short, IndexType>());
    assert(test_linalg_copy_real<unsigned int, IndexType>());
    assert(test_linalg_copy_real<unsigned long, IndexType>());
    assert(test_linalg_copy_real<unsigned long long, IndexType>());

    assert(test_linalg_copy_real<signed char, IndexType>());
    assert(test_linalg_copy_real<signed short, IndexType>());
    assert(test_linalg_copy_real<signed int, IndexType>());
    assert(test_linalg_copy_real<signed long, IndexType>());
    assert(test_linalg_copy_real<signed long long, IndexType>());

    assert(test_linalg_copy_real<float, IndexType>());
    assert(test_linalg_copy_real<double, IndexType>());

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
