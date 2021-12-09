/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_MODULUS_HPP
#define TETL_FUNCTIONAL_MODULUS_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for computing remainders of divisions. Implements
/// operator% for type T.
/// https://en.cppreference.com/w/cpp/utility/functional/modulus
/// \group modulus
/// \module Utility
template <typename T = void>
struct modulus {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs % rhs; }
};

/// \group modulus
template <>
struct modulus<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(forward<T>(lhs) % forward<U>(rhs))) -> decltype(forward<T>(lhs) % forward<U>(rhs))
    {
        return forward<T>(lhs) % forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_MODULUS_HPP