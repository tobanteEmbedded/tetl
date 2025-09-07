// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

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
