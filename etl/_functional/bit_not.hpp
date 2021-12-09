/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_BIT_NOT_HPP
#define TETL_FUNCTIONAL_BIT_NOT_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing bitwise NOT.
/// Effectively calls operator~ on type T.
///
/// https://en.cppreference.com/w/cpp/utility/functional/bit_not
///
/// \group bit_not
/// \module Utility
template <typename T = void>
struct bit_not {
    [[nodiscard]] constexpr auto operator()(T const& arg) const -> T { return ~arg; }
};

/// \group bit_not
template <>
struct bit_not<void> {
    using is_transparent = void;

    template <typename T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const noexcept(noexcept(~forward<T>(arg)))
        -> decltype(~forward<T>(arg))
    {
        return ~forward<T>(arg);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_BIT_NOT_HPP