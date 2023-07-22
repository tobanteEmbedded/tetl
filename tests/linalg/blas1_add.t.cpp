// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_add_real() -> bool
{
    auto const zero_data  = etl::array<T, 4> {};
    auto const other_data = etl::array<T, 4> { T(1), T(2), T(3), T(4) };

    {
        // 1D static
        auto lhs = etl::mdspan<T const, etl::extents<IndexType, 4>> { zero_data.data() };
        auto rhs = etl::mdspan<T const, etl::extents<IndexType, 4>> { other_data.data() };

        auto out_data = etl::array<T, 4> {};
        auto out      = etl::mdspan<T, etl::extents<IndexType, 4>> { out_data.data() };
        etl::linalg::add(lhs, rhs, out);
        assert(out(0) == T(1));
        assert(out(1) == T(2));
        assert(out(2) == T(3));
        assert(out(3) == T(4));
    }

    {
        // 1D dynamic
        auto lhs = etl::mdspan<T const, etl::dextents<IndexType, 1>> { zero_data.data(), zero_data.size() };
        auto rhs = etl::mdspan<T const, etl::dextents<IndexType, 1>> { other_data.data(), other_data.size() };

        auto out_data = etl::array<T, 4> {};
        auto out      = etl::mdspan<T, etl::dextents<IndexType, 1>> { out_data.data(), out_data.size() };
        etl::linalg::add(lhs, rhs, out);
        assert(out(0) == T(1));
        assert(out(1) == T(2));
        assert(out(2) == T(3));
        assert(out(3) == T(4));
    }

    {
        // 2D static
        auto lhs = etl::mdspan<T const, etl::extents<IndexType, 2, 2>> { zero_data.data() };
        auto rhs = etl::mdspan<T const, etl::extents<IndexType, 2, 2>> { other_data.data() };

        auto out_data = etl::array<T, 4> {};
        auto out      = etl::mdspan<T, etl::extents<IndexType, 2, 2>> { out_data.data() };
        etl::linalg::add(lhs, rhs, out);
        assert(out(0, 0) == T(1));
        assert(out(0, 1) == T(2));
        assert(out(1, 0) == T(3));
        assert(out(1, 1) == T(4));
    }

    {
        // 2D dynamic
        auto lhs = etl::mdspan<T const, etl::dextents<IndexType, 2>> { zero_data.data(), 2, 2 };
        auto rhs = etl::mdspan<T const, etl::dextents<IndexType, 2>> { other_data.data(), 2, 2 };

        auto out_data = etl::array<T, 4> {};
        auto out      = etl::mdspan<T, etl::dextents<IndexType, 2>> { out_data.data(), 2, 2 };
        etl::linalg::add(lhs, rhs, out);
        assert(out(0, 0) == T(1));
        assert(out(0, 1) == T(2));
        assert(out(1, 0) == T(3));
        assert(out(1, 1) == T(4));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_add_real<unsigned char, IndexType>());
    assert(test_linalg_add_real<unsigned short, IndexType>());
    assert(test_linalg_add_real<unsigned int, IndexType>());
    assert(test_linalg_add_real<unsigned long, IndexType>());
    assert(test_linalg_add_real<unsigned long long, IndexType>());

    assert(test_linalg_add_real<signed char, IndexType>());
    assert(test_linalg_add_real<signed short, IndexType>());
    assert(test_linalg_add_real<signed int, IndexType>());
    assert(test_linalg_add_real<signed long, IndexType>());
    assert(test_linalg_add_real<signed long long, IndexType>());

    assert(test_linalg_add_real<float, IndexType>());
    assert(test_linalg_add_real<double, IndexType>());

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
