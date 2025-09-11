// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_DISJUNCTION_HPP
#define TETL_TYPE_TRAITS_DISJUNCTION_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/conditional.hpp>

namespace etl {

/// Forms the logical disjunction of the type traits B..., effectively
/// performing a logical OR on the sequence of traits.
/// \ingroup type_traits
template <typename... B>
struct disjunction : bool_constant<(B::value or ...)> { };

/// \ingroup type_traits
template <typename... B>
inline constexpr bool disjunction_v = disjunction<B...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_DISJUNCTION_HPP
