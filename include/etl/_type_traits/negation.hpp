/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_NEGATION_HPP
#define TETL_TYPE_TRAITS_NEGATION_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief Forms the logical negation of the type trait B.
template <typename B>
struct negation : etl::bool_constant<!bool(B::value)> { };

template <typename B>
inline constexpr bool negation_v = !bool(B::value);

} // namespace etl

#endif // TETL_TYPE_TRAITS_NEGATION_HPP
