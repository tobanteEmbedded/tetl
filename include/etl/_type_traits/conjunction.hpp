// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_CONJUNCTION_HPP
#define TETL_TYPE_TRAITS_CONJUNCTION_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/conditional.hpp>

namespace etl {

/// \brief Forms the logical conjunction of the type traits B..., effectively
/// performing a logical AND on the sequence of traits.
/// \ingroup type_traits
template <typename... B>
struct conjunction : bool_constant<(B::value and ...)> { };

/// \ingroup type_traits
/// \relates conjunction
template <typename... B>
inline constexpr bool conjunction_v = conjunction<B...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_CONJUNCTION_HPP
