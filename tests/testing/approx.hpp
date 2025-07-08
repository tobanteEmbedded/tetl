// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_TESTING_APPROX_HPP
#define TETL_TEST_TESTING_APPROX_HPP

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cmath;
#else
    #include <etl/cmath.hpp>
#endif

template <typename T>
constexpr auto approx(T a, T b, T epsilon = static_cast<T>(0.001)) -> bool
{
    return etl::fabs(a - b) < epsilon;
}

#define CHECK_APPROX(...) CHECK(::approx(__VA_ARGS__))

#endif // TETL_TEST_TESTING_APPROX_HPP
