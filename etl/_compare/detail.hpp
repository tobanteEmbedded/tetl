/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPARE_DETAIL_HPP
#define TETL_COMPARE_DETAIL_HPP

#include "etl/_cstdint/int_t.hpp"

#if defined(__cpp_impl_three_way_comparison)

namespace etl::detail {
enum struct order_result : int8_t { less = -1, equal = 0, greater = 1 };
enum struct compare_result : int8_t { unordered = -127 };
} // namespace etl::detail

#endif

#endif // TETL_COMPARE_DETAIL_HPP