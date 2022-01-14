/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_UTILITY_AS_CONST_HPP
#define TETL_UTILITY_AS_CONST_HPP

#include "etl/_type_traits/add_const.hpp"

namespace etl {
/// \brief Forms lvalue reference to const type of t.
template <typename T>
[[nodiscard]] constexpr auto as_const(T& t) noexcept -> add_const_t<T>&
{
    return t;
}

template <typename T>
constexpr auto as_const(T const&&) -> void
    = delete;

} // namespace etl

#endif // TETL_UTILITY_AS_CONST_HPP