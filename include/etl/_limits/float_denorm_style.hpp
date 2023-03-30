// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LIMITS_FLOAT_DENORM_STYLE_HPP
#define TETL_LIMITS_FLOAT_DENORM_STYLE_HPP

namespace etl {

enum float_denorm_style {
    denorm_indeterminate = -1,
    denorm_absent        = 0,
    denorm_present       = 1,
};

} // namespace etl

#endif // TETL_LIMITS_FLOAT_DENORM_STYLE_HPP
