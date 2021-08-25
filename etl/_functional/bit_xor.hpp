/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_BIT_XOR_HPP
#define TETL_FUNCTIONAL_BIT_XOR_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing bitwise XOR. Effectively calls
/// operator^ on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/bit_xor
/// \group bit_xor
/// \module Utility
template <typename T = void>
struct bit_xor {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
        -> T
    {
        return lhs ^ rhs;
    }
};

/// \group bit_xor
template <>
struct bit_xor<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) ^ etl::forward<U>(rhs))
    {
        return lhs ^ rhs;
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_BIT_XOR_HPP