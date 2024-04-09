// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_REMOVE_POINTER_HPP
#define TETL_TYPE_TRAITS_REMOVE_POINTER_HPP

namespace etl {

/// \brief Provides the member typedef type which is the type pointed to by T,
/// or, if T is not a pointer, then type is the same as T. The behavior of a
/// program that adds specializations for remove_pointer is undefined.
/// \ingroup type_traits
template <typename T>
struct remove_pointer {
    using type = T;
};

template <typename T>
struct remove_pointer<T*> {
    using type = T;
};

template <typename T>
struct remove_pointer<T* const> {
    using type = T;
};

template <typename T>
struct remove_pointer<T* volatile> {
    using type = T;
};

template <typename T>
struct remove_pointer<T* const volatile> {
    using type = T;
};

template <typename T>
using remove_pointer_t = typename remove_pointer<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_POINTER_HPP
