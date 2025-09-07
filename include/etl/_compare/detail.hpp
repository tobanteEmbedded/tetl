// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_COMPARE_DETAIL_HPP
#define TETL_COMPARE_DETAIL_HPP

#include <etl/_cstdint/int_t.hpp>

namespace etl::detail {

enum struct order_result : etl::int8_t {
    less    = -1,
    equal   = 0,
    greater = 1
};
enum struct compare_result : etl::int8_t {
    unordered = -127
};

} // namespace etl::detail

#endif // TETL_COMPARE_DETAIL_HPP
