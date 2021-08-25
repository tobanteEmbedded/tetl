/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_REMOVE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_REMOVE_REFERENCE_HPP

namespace etl {

/// \group remove_reference
template <typename T>
struct remove_reference {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_reference<T&> {
    using type = T;
};

/// \exclude
template <typename T>
struct remove_reference<T&&> {
    using type = T;
};

/// \group remove_reference
template <typename T>
using remove_reference_t = typename remove_reference<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_REFERENCE_HPP