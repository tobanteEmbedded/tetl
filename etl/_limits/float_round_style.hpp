/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_LIMITS_FLOAT_ROUND_STYLE_HPP
#define TETL_LIMITS_FLOAT_ROUND_STYLE_HPP

namespace etl {

enum float_round_style {
    round_indeterminate       = -1,
    round_toward_zero         = 0,
    round_to_nearest          = 1,
    round_toward_infinity     = 2,
    round_toward_neg_infinity = 3,
};

} // namespace etl

#endif // TETL_LIMITS_FLOAT_ROUND_STYLE_HPP