/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_MOVE_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_MOVE_CONSTRUCTIBLE_HPP

#include "etl/_type_traits/add_rvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_nothrow_constructible.hpp"

namespace etl {

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_nothrow_constructible<T, T&&>::value.
template <typename T>
struct is_nothrow_move_constructible
    : is_nothrow_constructible<T, add_rvalue_reference_t<T>> {
};

template <typename T>
inline constexpr bool is_nothrow_move_constructible_v
    = is_nothrow_move_constructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_MOVE_CONSTRUCTIBLE_HPP