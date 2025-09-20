// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TEST_TESTING_APPROX_HPP
#define TETL_TEST_TESTING_APPROX_HPP

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
#endif

template <typename T>
constexpr auto approx(T a, T b, T epsilon = static_cast<T>(0.0001)) -> bool
{
    return etl::fabs(a - b) < epsilon;
}

#define CHECK_APPROX(...) CHECK(::approx(__VA_ARGS__))

#endif // TETL_TEST_TESTING_APPROX_HPP
