// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_add_real() -> bool
{
    auto const zeroData  = etl::array<T, 4>{};
    auto const otherData = etl::array<T, 4>{T(1), T(2), T(3), T(4)};

    {
        // 1D static
        auto lhs = etl::mdspan<T const, etl::extents<IndexType, 4>>{zeroData.data()};
        auto rhs = etl::mdspan<T const, etl::extents<IndexType, 4>>{otherData.data()};

        auto outData = etl::array<T, 4>{};
        auto out     = etl::mdspan<T, etl::extents<IndexType, 4>>{outData.data()};
        etl::linalg::add(lhs, rhs, out);
        CHECK(out(0) == T(1));
        CHECK(out(1) == T(2));
        CHECK(out(2) == T(3));
        CHECK(out(3) == T(4));

        outData.fill(T(0));
        etl::linalg::add(lhs, etl::linalg::scaled(T(2), rhs), out);
        CHECK(out(0) == T(2));
        CHECK(out(1) == T(4));
        CHECK(out(2) == T(6));
        CHECK(out(3) == T(8));
    }

    {
        // 1D dynamic
        auto lhs = etl::mdspan<T const, etl::dextents<IndexType, 1>>{zeroData.data(), zeroData.size()};
        auto rhs = etl::mdspan<T const, etl::dextents<IndexType, 1>>{otherData.data(), otherData.size()};

        auto outData = etl::array<T, 4>{};
        auto out     = etl::mdspan<T, etl::dextents<IndexType, 1>>{outData.data(), outData.size()};
        etl::linalg::add(lhs, rhs, out);
        CHECK(out(0) == T(1));
        CHECK(out(1) == T(2));
        CHECK(out(2) == T(3));
        CHECK(out(3) == T(4));
    }

    {
        // 2D static
        auto lhs = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{zeroData.data()};
        auto rhs = etl::mdspan<T const, etl::extents<IndexType, 2, 2>>{otherData.data()};

        auto outData = etl::array<T, 4>{};
        auto out     = etl::mdspan<T, etl::extents<IndexType, 2, 2>>{outData.data()};
        etl::linalg::add(lhs, rhs, out);
        CHECK(out(0, 0) == T(1));
        CHECK(out(0, 1) == T(2));
        CHECK(out(1, 0) == T(3));
        CHECK(out(1, 1) == T(4));
    }

    {
        // 2D dynamic
        auto lhs = etl::mdspan<T const, etl::dextents<IndexType, 2>>{zeroData.data(), 2, 2};
        auto rhs = etl::mdspan<T const, etl::dextents<IndexType, 2>>{otherData.data(), 2, 2};

        auto outData = etl::array<T, 4>{};
        auto out     = etl::mdspan<T, etl::dextents<IndexType, 2>>{outData.data(), 2, 2};
        etl::linalg::add(lhs, rhs, out);
        CHECK(out(0, 0) == T(1));
        CHECK(out(0, 1) == T(2));
        CHECK(out(1, 0) == T(3));
        CHECK(out(1, 1) == T(4));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    // CHECK(test_linalg_add_real<unsigned char, IndexType>());
    // CHECK(test_linalg_add_real<unsigned short, IndexType>());
    CHECK(test_linalg_add_real<unsigned int, IndexType>());
    CHECK(test_linalg_add_real<unsigned long, IndexType>());
    CHECK(test_linalg_add_real<unsigned long long, IndexType>());

    // CHECK(test_linalg_add_real<signed char, IndexType>());
    // CHECK(test_linalg_add_real<signed short, IndexType>());
    CHECK(test_linalg_add_real<signed int, IndexType>());
    CHECK(test_linalg_add_real<signed long, IndexType>());
    CHECK(test_linalg_add_real<signed long long, IndexType>());

    CHECK(test_linalg_add_real<float, IndexType>());
    CHECK(test_linalg_add_real<double, IndexType>());

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
