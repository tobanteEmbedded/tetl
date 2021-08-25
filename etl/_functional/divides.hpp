/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_DIVIDES_HPP
#define TETL_FUNCTIONAL_DIVIDES_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing division. Effectively calls operator/
/// on two instances of type T.
/// https://en.cppreference.com/w/cpp/utility/functional/divides
/// \group divides
/// \module Utility
template <typename T = void>
struct divides {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
        -> T
    {
        return lhs / rhs;
    }
};

/// \group divides
template <>
struct divides<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) / etl::forward<U>(rhs))
    {
        return lhs / rhs;
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_DIVIDES_HPP