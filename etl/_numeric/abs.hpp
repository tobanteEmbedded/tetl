/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_ABS_HPP
#define TETL_NUMERIC_ABS_HPP

#include "etl/_limits/numeric_limits.hpp"

namespace etl {

/// \brief Returns the absolute value.
template <typename Type>
[[nodiscard]] constexpr auto abs(Type input) noexcept -> Type
{
    using limits = numeric_limits<Type>;
    if constexpr (limits::is_signed || !limits::is_specialized) {
        if (input < 0) { return static_cast<Type>(-input); }
        return input;
    } else {
        return input;
    }
}

} // namespace etl

#endif // TETL_NUMERIC_ABS_HPP