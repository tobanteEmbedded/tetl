/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MATH_SIGN_HPP
#define TETL_MATH_SIGN_HPP

namespace etl::detail {

template <typename T>
[[nodiscard]] constexpr auto sign(T val)
{
    if (val < 0) { return T(-1); }
    return T(1);
}
} // namespace etl::detail

#endif // TETL_MATH_SIGN_HPP
