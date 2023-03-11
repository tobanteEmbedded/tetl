/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_AGGREGATE_HPP
#define TETL_TYPE_TRAITS_IS_AGGREGATE_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

template <typename T>
struct is_aggregate : bool_constant<__is_aggregate(remove_cv_t<T>)> { };

template <typename T>
inline constexpr bool is_aggregate_v = __is_aggregate(remove_cv_t<T>);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_AGGREGATE_HPP
