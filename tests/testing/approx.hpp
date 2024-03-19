// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_TESTING_APPROX_HPP
#define TETL_TEST_TESTING_APPROX_HPP

#include <etl/cmath.hpp>

template <typename T>
constexpr auto approx(T a, T b, T epsilon = static_cast<T>(0.001)) -> bool
{
    return etl::fabs(a - b) < epsilon;
}

#define ASSERT_APPROX(...) ASSERT(::approx(__VA_ARGS__))

#endif // TETL_TEST_TESTING_APPROX_HPP
