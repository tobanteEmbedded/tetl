/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_REMOVE_CONST_HPP
#define TETL_TYPE_TRAITS_REMOVE_CONST_HPP

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except that
/// its topmost cv-qualifiers are removed. Removes the topmost const.
/// \details The behavior of a program that adds specializations for any of the
/// templates described on this page is undefined.
template <typename Type>
struct remove_const {
    using type = Type;
};

/// \exclude
template <typename Type>
struct remove_const<Type const> {
    using type = Type;
};

template <typename T>
using remove_const_t = typename etl::remove_const<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_CONST_HPP
