/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_PLUS_HPP
#define TETL_FUNCTIONAL_PLUS_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing addition. Effectively calls operator+
/// on two instances of type T.
/// https://en.cppreference.com/w/cpp/utility/functional/plus
template <typename T = void>
struct plus {
    /// \brief Returns the sum of lhs and rhs.
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs + rhs; }
};

template <>
struct plus<void> {
    using is_transparent = void;

    /// \brief Returns the sum of lhs and rhs.
    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(forward<T>(lhs) + forward<U>(rhs))) -> decltype(forward<T>(lhs) + forward<U>(rhs))
    {
        return forward<T>(lhs) + forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_PLUS_HPP
