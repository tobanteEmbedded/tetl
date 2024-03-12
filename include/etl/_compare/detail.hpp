// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_DETAIL_HPP
#define TETL_COMPARE_DETAIL_HPP

#include "etl/_cstdint/int_t.hpp"

namespace etl::detail {
enum struct order_result : int8_t {
    less    = -1,
    equal   = 0,
    greater = 1
};
enum struct compare_result : int8_t {
    unordered = -127
};
} // namespace etl::detail

#endif // TETL_COMPARE_DETAIL_HPP
