/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TEST_CMATH_HELPER_HPP
#define TETL_TEST_CMATH_HELPER_HPP

#include "etl/cassert.hpp"
#include "etl/cmath.hpp"

#include <stdio.h>
#include <stdlib.h>

template <typename T>
constexpr auto approx(T a, T b, T epsilon = static_cast<T>(0.001)) -> bool
{
    return etl::fabs(a - b) < epsilon;
}

namespace etl {
inline auto tetl_assert_handler(etl::assert_msg const& msg) -> void
{
    ::printf("ASSERTION: %s:%d - %s\n", msg.file, msg.line, msg.expression);
    ::exit(1); // NOLINT
}

} // namespace etl

#endif // TETL_TEST_CMATH_HELPER_HPP