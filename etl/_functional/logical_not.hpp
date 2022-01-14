/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_LOGICAL_NOT_HPP
#define TETL_FUNCTIONAL_LOGICAL_NOT_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing logical NOT (logical negation).
/// Effectively calls operator! for type T.
/// https://en.cppreference.com/w/cpp/utility/functional/logical_not
template <typename T = void>
struct logical_not {
    [[nodiscard]] constexpr auto operator()(T const& arg) const -> bool { return !arg; }
};

template <>
struct logical_not<void> {
    using is_transparent = void;

    template <typename T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const noexcept(noexcept(!forward<T>(arg)))
        -> decltype(!forward<T>(arg))
    {
        return !forward<T>(arg);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_LOGICAL_NOT_HPP