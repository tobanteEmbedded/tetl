// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_DERIVED_FROM_HPP
#define TETL_CONCEPTS_DERIVED_FROM_HPP

#include "etl/_type_traits/is_base_of.hpp"
#include "etl/_type_traits/is_convertible.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept derived_from<Derived, Base> is satisfied if and only if
/// Base is a class type that is either Derived or a public and unambiguous base
/// of Derived, ignoring cv-qualifiers. Note that this behaviour is different to
/// is_base_of when Base is a private or protected base of Derived.
template <typename Derived, typename Base>
concept derived_from = is_base_of_v<Base, Derived> && is_convertible_v<const volatile Derived*, const volatile Base*>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_DERIVED_FROM_HPP
