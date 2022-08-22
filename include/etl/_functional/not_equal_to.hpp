/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_NOT_EQUAL_TO_HPP
#define TETL_FUNCTIONAL_NOT_EQUAL_TO_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator!= on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/not_equal_to
template <typename T = void>
struct not_equal_to {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs != rhs; }
};

template <>
struct not_equal_to<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(forward<T>(lhs) != forward<U>(rhs))) -> decltype(forward<T>(lhs) != forward<U>(rhs))
    {
        return forward<T>(lhs) != forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_NOT_EQUAL_TO_HPP
