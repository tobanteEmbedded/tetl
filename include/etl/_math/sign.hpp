// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_MATH_SIGN_HPP
#define TETL_MATH_SIGN_HPP

namespace etl::detail {

template <typename T>
[[nodiscard]] constexpr auto sign(T val)
{
    if (val < 0) {
        return T(-1);
    }
    return T(1);
}
} // namespace etl::detail

#endif // TETL_MATH_SIGN_HPP
