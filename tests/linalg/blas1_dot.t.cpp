// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "testing/approx.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/complex.hpp>
    #include <etl/linalg.hpp>
    #include <etl/mdspan.hpp>
#endif

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_dot() -> bool
{
    {
        auto lBuf = etl::array{T(1), T(3), T(5)};
        auto lhs  = etl::mdspan<T, etl::extents<IndexType, 3>>{lBuf.data()};

        auto rBuf = etl::array{T(4), T(2), T(1)};
        auto rhs  = etl::mdspan<T, etl::extents<IndexType, 3>>{rBuf.data()};

        {
            auto const dot = etl::linalg::dot(lhs, rhs, T{0});
            CHECK_SAME_TYPE(decltype(dot), T const);
            CHECK(dot == T{15});
        }

        {
            auto const dot = etl::linalg::dot(lhs, rhs);
            CHECK_SAME_TYPE(decltype(dot), etl::add_const_t<decltype(T{} * T{})>);
            CHECK(dot == T{15});
        }
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    CHECK(test_dot<unsigned char, IndexType>());
    CHECK(test_dot<unsigned short, IndexType>());
    CHECK(test_dot<unsigned int, IndexType>());
    CHECK(test_dot<unsigned long, IndexType>());
    CHECK(test_dot<unsigned long long, IndexType>());

    CHECK(test_dot<signed char, IndexType>());
    CHECK(test_dot<signed short, IndexType>());
    CHECK(test_dot<signed int, IndexType>());
    CHECK(test_dot<signed long, IndexType>());
    CHECK(test_dot<signed long long, IndexType>());

    CHECK(test_dot<float, IndexType>());
    CHECK(test_dot<double, IndexType>());

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
