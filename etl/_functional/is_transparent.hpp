/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_IS_TRANSPARENT_HPP
#define TETL_FUNCTIONAL_IS_TRANSPARENT_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {
template <typename T, typename, typename = void>
struct is_transparent : etl::false_type {
};

/// \brief is_transparent
/// \group is_transparent
/// \module Utility
template <typename T, typename U>
struct is_transparent<T, U,
    etl::conditional_t<etl::is_same_v<typename T::is_transparent, void>, void,
        bool>> : etl::true_type {
};

/// \group is_transparent
template <typename T, typename U>
inline constexpr auto transparent_v = is_transparent<T, U>::value;

} // namespace detail

} // namespace etl

#endif // TETL_FUNCTIONAL_IS_TRANSPARENT_HPP