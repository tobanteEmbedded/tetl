// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_REMOVE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_REMOVE_REFERENCE_HPP

namespace etl {

/// \ingroup type_traits
template <typename T>
struct remove_reference {
    using type = T;
};

/// \ingroup type_traits
template <typename T>
struct remove_reference<T&> {
    using type = T;
};

/// \ingroup type_traits
template <typename T>
struct remove_reference<T&&> {
    using type = T;
};

/// \ingroup type_traits
template <typename T>
using remove_reference_t = typename etl::remove_reference<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_REMOVE_REFERENCE_HPP
