/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_REMOVE_CV_HPP
#define TETL_TYPE_TRAITS_REMOVE_CV_HPP

#include "etl/_type_traits/remove_const.hpp"
#include "etl/_type_traits/remove_volatile.hpp"

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except that
/// its topmost cv-qualifiers are removed. Removes the topmost const, or the
/// topmost volatile, or both, if present.
/// \details The behavior of a program that adds specializations for any of the
/// templates described on this page is undefined.
/// \group remove_cv
template <typename Type>
struct remove_cv {
    using type = remove_const_t<remove_volatile_t<Type>>;
};

/// \group remove_cv
template <typename T>
using remove_cv_t = typename remove_cv<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_CV_HPP