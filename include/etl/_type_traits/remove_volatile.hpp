// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_REMOVE_VOLATILE_HPP
#define TETL_TYPE_TRAITS_REMOVE_VOLATILE_HPP

namespace etl {

/// Provides the member typedef type which is the same as T, except that
/// its topmost cv-qualifiers are removed. Removes the topmost volatile.
///
/// The behavior of a program that adds specializations for any of the
/// templates described on this page is undefined.
///
/// \ingroup type_traits
template <typename Type>
struct remove_volatile {
    using type = Type;
};

template <typename Type>
struct remove_volatile<Type volatile> {
    using type = Type;
};

/// \ingroup type_traits
template <typename T>
using remove_volatile_t = typename remove_volatile<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_VOLATILE_HPP
