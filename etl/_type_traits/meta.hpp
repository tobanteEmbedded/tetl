/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_META_HPP
#define TETL_TYPE_TRAITS_META_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl::detail {

template <typename...>
struct meta_or;

template <>
struct meta_or<> : false_type {
};

template <typename BF1>
struct meta_or<BF1> : BF1 {
};

template <typename BF1, typename BF2>
struct meta_or<BF1, BF2> : conditional<BF1::value, BF1, BF2>::type {
};

template <typename BF1, typename BF2, typename BF3, typename... BRest>
struct meta_or<BF1, BF2, BF3, BRest...>
    : conditional<BF1::value, BF1, meta_or<BF2, BF3, BRest...>>::type {
};

template <typename... BRest>
inline constexpr bool meta_or_v = meta_or<BRest...>::value;

template <typename...>
struct meta_and;

template <>
struct meta_and<> : true_type {
};

template <typename BF1>
struct meta_and<BF1> : BF1 {
};

template <typename BF1, typename BF2>
struct meta_and<BF1, BF2> : conditional<BF1::value, BF2, BF1>::type {
};

template <typename BF1, typename BF2, typename BF3, typename... BRest>
struct meta_and<BF1, BF2, BF3, BRest...>
    : conditional<BF1::value, meta_and<BF2, BF3, BRest...>, BF1>::type {
};

template <typename... BRest>
inline constexpr bool meta_and_v = meta_and<BRest...>::value;

template <typename P>
struct meta_not : bool_constant<!bool(P::value)> {
};

} // namespace etl::detail

#endif // TETL_TYPE_TRAITS_META_HPP