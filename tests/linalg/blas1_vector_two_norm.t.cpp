// SPDX-License-Identifier: BSL-1.0

#include <etl/linalg.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/mdspan.hpp>

#include "testing/testing.hpp"

template <typename T, typename IndexType>
[[nodiscard]] static constexpr auto test_linalg_vector_two_norm_real() -> bool
{
    auto const data = etl::array<T, 4>{T(2), T(2), T(2), T(2)};
    {
        // static extents
        auto const vec = etl::mdspan<T const, etl::extents<IndexType, 4>>{data.data()};
        assert(etl::linalg::vector_two_norm(vec) == T(4));
        assert(etl::linalg::vector_two_norm(etl::linalg::scaled(T(2), vec)) == T(8));

        assert(etl::linalg::vector_two_norm(vec, T(0)) == T(4));
        assert(etl::linalg::vector_two_norm(etl::linalg::scaled(T(2), vec), T(0)) == T(8));
    }

    return true;
}

template <typename IndexType>
[[nodiscard]] static constexpr auto test_index_type() -> bool
{
    assert(test_linalg_vector_two_norm_real<float, IndexType>());
    assert(test_linalg_vector_two_norm_real<double, IndexType>());

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
    STATIC_CHECK(test_all());
    return EXIT_SUCCESS;
}
