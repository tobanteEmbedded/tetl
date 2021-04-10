/*
Copyright (c) Tobias Hienzsch. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CONCEPTS_HPP
#define TAETL_CONCEPTS_HPP

#include "etl/cstddef.hpp"
#include "etl/type_traits.hpp"
#include "etl/version.hpp"

#if defined(TAETL_CPP_STANDARD_20) && defined(__cpp_concepts)
namespace etl
{
namespace detail
{
template <typename T, typename U>
concept same_helper = ::etl::is_same_v<T, U>;
}

/// \brief The concept same_as<T, U> is satisfied if and only if T and U denote
/// the same type. same_as<T, U> subsumes same_as<U, T> and vice versa.
template <typename T, typename U>
concept same_as = detail::same_helper<T, U> && detail::same_helper<U, T>;

/// \brief The concept derived_from<Derived, Base> is satisfied if and only if
/// Base is a class type that is either Derived or a public and unambiguous base
/// of Derived, ignoring cv-qualifiers. Note that this behaviour is different to
/// is_base_of when Base is a private or protected base of Derived.
template <typename Derived, typename Base>
concept derived_from
  = is_base_of_v<Base, Derived> && is_convertible_v<const volatile Derived*,
                                                    const volatile Base*>;

/// \brief The concept convertible_to<From, To> specifies that an expression of
/// the same type and value category as those of declval<From>() can be
/// implicitly and explicitly converted to the type To, and the two forms of
/// conversion are equivalent.
template <typename From, typename To>
concept convertible_to
  = is_convertible_v<From, To> && requires(add_rvalue_reference_t<From> (&f)())
{
  static_cast<To>(f());
};

/// \brief The concept integral<T> is satisfied if and only if T is an integral
/// type.
template <typename T>
concept integral = is_integral_v<T>;

/// \brief The concept signed_integral<T> is satisfied if and only if T is an
/// integral type and is_signed_v<T> is true.
template <typename T>
concept signed_integral = integral<T> && is_signed_v<T>;

/// \brief The concept unsigned_integral<T> is satisfied if and only if T is an
/// integral type and is_signed_v<T> is false.
template <typename T>
concept unsigned_integral = integral<T> && is_unsigned_v<T>;

/// \brief The concept floating_point<T> is satisfied if and only if T is a
/// floating-point type.
template <typename T>
concept floating_point = is_floating_point_v<T>;

/// \brief The concept destructible specifies the concept of all types whose
/// instances can safely be destroyed at the end of their lifetime (including
/// reference types).
template <typename T>
concept destructible = is_nothrow_destructible_v<T>;

/// \brief The constructible_from concept specifies that a variable of type T
/// can be initialized with the given set of argument types Args....
template <typename T, typename... Args>
concept constructible_from = destructible<T> && is_constructible_v<T, Args...>;

/// \brief The default_initializable concept checks whether variables of type T
/// can be value-initialized (T() is well-formed); direct-list-initialized from
/// an empty initializer list (T{} is well-formed); and default-initialized (T
/// t; is well-formed). Access checking is performed as if in a context
/// unrelated to T. Only the validity of the immediate context of the variable
/// initialization is considered.
// clang-format off
template <typename T>
concept default_initializable =
  constructible_from<T> &&
  requires { T {}; } &&
  requires { ::new (static_cast<void*>(nullptr)) T; };
// clang-format on

/// \brief The concept move_constructible is satisfied if T is a reference type,
/// or if it is an object type where an object of that type can be constructed
/// from an rvalue of that type in both direct- and copy-initialization
/// contexts, with the usual semantics.
///
/// https://en.cppreference.com/w/cpp/concepts/move_constructible
template <typename T>
concept move_constructible = constructible_from<T, T> && convertible_to<T, T>;

/// \brief The concept copy_constructible is satisfied if T is an lvalue
/// reference type, or if it is a move_constructible object type where an object
/// of that type can constructed from a (possibly const) lvalue or const rvalue
/// of that type in both direct- and copy-initialization contexts with the usual
/// semantics (a copy is constructed with the source unchanged).
// clang-format off
template <class T>
concept copy_constructible =
  move_constructible<T> &&
  constructible_from<T, T&> && convertible_to<T&, T> &&
  constructible_from<T, const T&> && convertible_to<const T&, T> &&
  constructible_from<T, const T> && convertible_to<const T, T>;
// clang-format on

}  // namespace etl

#endif

#endif  // TAETL_CONCEPTS_HPP