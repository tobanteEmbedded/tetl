/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
