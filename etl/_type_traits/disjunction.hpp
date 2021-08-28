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
template <typename... B>
struct disjunction : etl::bool_constant<(B::value || ...)> {
};

/// \group disjunction
template <typename... B>
inline constexpr bool disjunction_v = (B::value || ...);

} // namespace etl

#endif // TETL_TYPE_TRAITS_DISJUNCTION_HPP