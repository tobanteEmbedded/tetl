/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_GREATER_EQUAL_HPP
#define TETL_FUNCTIONAL_GREATER_EQUAL_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator>= on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/greater_equal
template <typename T = void>
struct greater_equal {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs >= rhs; }
};

template <>
struct greater_equal<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(forward<T>(lhs) >= forward<U>(rhs))) -> decltype(forward<T>(lhs) >= forward<U>(rhs))
    {
        return forward<T>(lhs) >= forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_GREATER_EQUAL_HPP