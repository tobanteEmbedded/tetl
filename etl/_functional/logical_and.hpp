/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_LOGICAL_AND_HPP
#define TETL_FUNCTIONAL_LOGICAL_AND_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing logical AND (logical conjunction).
/// Effectively calls operator&& on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/logical_and
/// \group logical_and
/// \module Utility
template <typename T = void>
struct logical_and {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> bool { return lhs && rhs; }
};

/// \group logical_and
template <>
struct logical_and<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) && etl::forward<U>(rhs))
    {
        return lhs && rhs;
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_LOGICAL_AND_HPP