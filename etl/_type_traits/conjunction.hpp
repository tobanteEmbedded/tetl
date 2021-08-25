/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_CONJUNCTION_HPP
#define TETL_TYPE_TRAITS_CONJUNCTION_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl {

/// \brief Forms the logical conjunction of the type traits B..., effectively
/// performing a logical AND on the sequence of traits.
/// \group conjunction
template <typename...>
struct conjunction : true_type {
};

/// \exclude
template <typename B1>
struct conjunction<B1> : B1 {
};

/// \exclude
template <typename B1, typename... Bn>
struct conjunction<B1, Bn...>
    : conditional_t<bool(B1::value), conjunction<Bn...>, B1> {
};

/// \group conjunction
template <typename... B>
inline constexpr bool conjunction_v = conjunction<B...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_CONJUNCTION_HPP