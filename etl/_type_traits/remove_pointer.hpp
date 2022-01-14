/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_REMOVE_POINTER_HPP
#define TETL_TYPE_TRAITS_REMOVE_POINTER_HPP

namespace etl {

/// \brief Provides the member typedef type which is the type pointed to by T,
/// or, if T is not a pointer, then type is the same as T. The behavior of a
/// program that adds specializations for remove_pointer is undefined.
template <typename T>
struct remove_pointer {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_pointer<T*> {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_pointer<T* const> {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_pointer<T* volatile> {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_pointer<T* const volatile> {
    using type = T;
};

template <typename T>
using remove_pointer_t = typename etl::remove_pointer<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_POINTER_HPP