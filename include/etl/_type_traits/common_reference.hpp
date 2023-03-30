// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_COMMON_REFERENCE_HPP
#define TETL_TYPE_TRAITS_COMMON_REFERENCE_HPP

#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

/// \brief The class template basic_common_reference is a customization point
/// that allows users to influence the result of common_reference for user-defined
/// types (typically proxy references). The primary template is empty.
template <typename T, typename U, template <typename> typename TQ, template <typename> typename UQ>
struct basic_common_reference { };

/// \brief Determines the common reference type of the types T..., that is, the type to which all the types in T... can
/// be converted or bound. If such a type exists (as determined according to the rules below), the member type names
/// that type. Otherwise, there is no member type. The behavior is undefined if any of the types in T... is an
/// incomplete type other than (possibly cv-qualified) void.
template <typename... T>
struct common_reference;

// if sizeof...(T) is zero
template <>
struct common_reference<> { };

// if sizeof...(T) is one
template <typename T>
struct common_reference<T> {
    using type = T;
};

template <typename... T>
using common_reference_t = typename common_reference<T...>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_COMMON_REFERENCE_HPP
