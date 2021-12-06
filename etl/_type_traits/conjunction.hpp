/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_CONJUNCTION_HPP
#define TETL_TYPE_TRAITS_CONJUNCTION_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"

namespace etl {

/// \group conjunction
template <typename... B>
inline constexpr bool conjunction_v = (B::value && ...);

/// \brief Forms the logical conjunction of the type traits B..., effectively
/// performing a logical AND on the sequence of traits.
/// \group conjunction
template <typename... B>
struct conjunction : bool_constant<conjunction_v<B...>> {
};

} // namespace etl

#endif // TETL_TYPE_TRAITS_CONJUNCTION_HPP