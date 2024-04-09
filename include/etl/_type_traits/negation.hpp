// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_NEGATION_HPP
#define TETL_TYPE_TRAITS_NEGATION_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Forms the logical negation of the type trait B.
template <typename B>
struct negation : bool_constant<not static_cast<bool>(B::value)> { };

template <typename B>
inline constexpr bool negation_v = not static_cast<bool>(B::value);

} // namespace etl

#endif // TETL_TYPE_TRAITS_NEGATION_HPP
