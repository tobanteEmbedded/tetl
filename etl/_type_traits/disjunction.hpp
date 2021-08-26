/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_DISJUNCTION_HPP
#define TETL_TYPE_TRAITS_DISJUNCTION_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl {

/// \brief Forms the logical disjunction of the type traits B..., effectively
/// performing a logical OR on the sequence of traits.
/// \group disjunction
template <typename...>
struct disjunction : false_type {
};

/// \exclude
template <typename BF1>
struct disjunction<BF1> : BF1 {
};

/// \exclude
template <typename BF1, typename... Bn>
struct disjunction<BF1, Bn...>
    : conditional_t<bool(BF1::value), BF1, disjunction<Bn...>> {
};

/// \group disjunction
template <typename... B>
inline constexpr bool disjunction_v = disjunction<B...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_DISJUNCTION_HPP