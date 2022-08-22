/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_UNION_HPP
#define TETL_TYPE_TRAITS_IS_UNION_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

template <typename T>
struct is_union : bool_constant<__is_union(T)> {
};

template <typename T>
inline constexpr bool is_union_v = __is_union(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNION_HPP
