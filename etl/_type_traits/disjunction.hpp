/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_DISJUNCTION_HPP
#define TETL_TYPE_TRAITS_DISJUNCTION_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl {

template <typename... B>
inline constexpr bool disjunction_v = (B::value || ...);

/// \brief Forms the logical disjunction of the type traits B..., effectively
/// performing a logical OR on the sequence of traits.
template <typename... B>
struct disjunction : bool_constant<disjunction_v<B...>> {
};

} // namespace etl

#endif // TETL_TYPE_TRAITS_DISJUNCTION_HPP
