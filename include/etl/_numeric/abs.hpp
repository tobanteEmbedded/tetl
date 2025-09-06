// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch
#ifndef TETL_NUMERIC_ABS_HPP
#define TETL_NUMERIC_ABS_HPP

#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \brief Returns the absolute value.
/// \ingroup numeric
template <typename Type>
[[nodiscard]] constexpr auto abs(Type input) noexcept -> Type
{
    using limits = etl::numeric_limits<Type>;
    if constexpr (limits::is_signed or not limits::is_specialized) {
        if (input < 0) {
            return static_cast<Type>(-input);
        }
        return input;
    } else {
        return input;
    }
}

} // namespace etl

#endif // TETL_NUMERIC_ABS_HPP
