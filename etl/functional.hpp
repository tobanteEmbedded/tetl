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

#ifndef TAETL_FUNCTIONAL_HPP
#define TAETL_FUNCTIONAL_HPP

#include "etl/cstddef.hpp"
#include "etl/iterator.hpp"
#include "etl/new.hpp"
#include "etl/utility.hpp"

#include "etl/detail/algo_search.hpp"

namespace etl
{
namespace detail
{
template <typename T, typename, typename = void>
struct is_transparent : ::etl::false_type
{
};

template <typename T, typename U>
struct is_transparent<
  T, U,
  ::etl::conditional_t<::etl::is_same_v<typename T::is_transparent, void>, void,
                       bool>> : ::etl::true_type
{
};

template <typename T, typename U>
inline constexpr auto transparent_v = is_transparent<T, U>::value;

}  // namespace detail

/// \brief Function object for performing addition. Effectively calls operator+
/// on two instances of type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/plus
template <typename T = void>
struct plus
{
  /// \brief Returns the sum of lhs and rhs.
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs + rhs;
  }
};

/// \brief Function object for performing addition. Effectively calls operator+
/// on two instances of type T. The standard library provides a specialization
/// of etl::plus when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/plus_void
template <>
struct plus<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  /// \brief Returns the sum of lhs and rhs.
  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) + etl::forward<U>(rhs))
  {
    return lhs + rhs;
  }
};

/// \brief Function object for performing subtraction. Effectively calls
/// operator- on two instances of type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/minus
template <typename T = void>
struct minus
{
  /// \brief Returns the difference between lhs and rhs.
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs - rhs;
  }
};

/// \brief Function object for performing subtraction. Effectively calls
/// operator- on two instances of type T. The standard library provides a
/// specialization of etl::minus when T is not specified, which leaves the
/// parameter types and return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/minus_void
template <>
struct minus<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  /// \brief Returns the difference between lhs and rhs.
  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) - etl::forward<U>(rhs))
  {
    return lhs - rhs;
  }
};

/// \brief Function object for performing multiplication. Effectively calls
/// operator* on two instances of type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/multiplies
template <typename T = void>
struct multiplies
{
  /// \brief Returns the product between lhs and rhs.
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs * rhs;
  }
};

/// \brief Function object for performing multiplication. Effectively calls
/// operator* on two instances of type T. The standard library provides a
/// specialization of etl::multiplies when T is not specified, which leaves the
/// parameter types and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/multiplies_void
template <>
struct multiplies<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  /// \brief Returns the product between lhs and rhs.
  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) * etl::forward<U>(rhs))
  {
    return lhs * rhs;
  }
};

/// \brief Function object for performing division. Effectively calls operator/
/// on two instances of type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/divides
template <typename T = void>
struct divides
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs / rhs;
  }
};

/// \brief Function object for performing division. Effectively calls operator/
/// on two instances of type T. The standard library provides a specialization
/// of etl::divides when T is not specified, which leaves the parameter types
/// and return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/divides_void
template <>
struct divides<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) / etl::forward<U>(rhs))
  {
    return lhs / rhs;
  }
};

/// \brief Function object for computing remainders of divisions. Implements
/// operator% for type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/modulus
template <typename T = void>
struct modulus
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs % rhs;
  }
};

/// \brief Function object for computing remainders of divisions. Implements
/// operator% for type T. The standard library provides a specialization of
/// etl::modulus when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/modulus_void
template <>
struct modulus<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) % etl::forward<U>(rhs))
  {
    return lhs % rhs;
  }
};

/// \brief Function object for performing negation. Effectively calls operator-
/// on an instance of type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/negate
template <typename T = void>
struct negate
{
  [[nodiscard]] constexpr auto operator()(T const& arg) const -> T
  {
    return -arg;
  }
};

/// \brief Function object for performing negation. Effectively calls operator-
/// on an instance of type T. The standard library provides a specialization of
/// etl::negate when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/negate_void
template <>
struct negate<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T>
  [[nodiscard]] constexpr auto operator()(T&& arg) const
    -> decltype(-etl::forward<T>(arg))
  {
    return -arg;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator== on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/equal_to
template <typename T = void>
struct equal_to
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs == rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator== on type T. The standard library provides a specialization
/// of etl::equal_to when T is not specified, which leaves the parameter types
/// and return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/equal_to_void
template <>
struct equal_to<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) == etl::forward<U>(rhs))
  {
    return lhs == rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator!= on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/not_equal_to
template <typename T = void>
struct not_equal_to
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs != rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator!= on type T. The standard library provides a specialization
/// of etl::not_equal_to when T is not specified, which leaves the parameter
/// types and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/not_equal_to_void
template <>
struct not_equal_to<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) != etl::forward<U>(rhs))
  {
    return lhs != rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator> on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/greater
template <typename T = void>
struct greater
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs > rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator> on type T. The standard library provides a specialization
/// of etl::greater when T is not specified, which leaves the parameter types
/// and return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/greater_void
template <>
struct greater<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) > etl::forward<U>(rhs))
  {
    return lhs > rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator>= on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/greater_equal
template <typename T = void>
struct greater_equal
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs >= rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator> on type T. The standard library provides a specialization
/// of etl::greater_equal when T is not specified, which leaves the parameter
/// types and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/greater_equal_void
template <>
struct greater_equal<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) >= etl::forward<U>(rhs))
  {
    return lhs >= rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator< on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/less
template <typename T = void>
struct less
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
    -> bool
  {
    return lhs < rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator< on type T. The standard library provides a specialization
/// of etl::less when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/less_void
template <>
struct less<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) < etl::forward<U>(rhs))
  {
    return lhs < rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator<= on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/less_equal
template <typename T = void>
struct less_equal
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
    -> bool
  {
    return lhs <= rhs;
  }
};

/// \brief Function object for performing comparisons. Unless specialised,
/// invokes operator< on type T. The standard library provides a specialization
/// of etl::less_equal when T is not specified, which leaves the parameter types
/// and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/less_equal_void
template <>
struct less_equal<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) <= etl::forward<U>(rhs))
  {
    return lhs <= rhs;
  }
};

/// \brief Function object for performing logical AND (logical conjunction).
/// Effectively calls operator&& on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/logical_and
template <typename T = void>
struct logical_and
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
    -> bool
  {
    return lhs && rhs;
  }
};

/// \brief Function object for performing logical AND (logical conjunction).
/// Effectively calls operator&& on type T. The standard library provides a
/// specialization of etl::logical_and when T is not specified, which leaves the
/// parameter types and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/logical_and_void
template <>
struct logical_and<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) && etl::forward<U>(rhs))
  {
    return lhs && rhs;
  }
};

/// \brief Function object for performing logical OR (logical disjunction).
/// Effectively calls operator|| on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/logical_or
template <typename T = void>
struct logical_or
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
    -> bool
  {
    return lhs || rhs;
  }
};

/// \brief Function object for performing logical OR (logical disjunction).
/// Effectively calls operator|| on type T. The standard library provides a
/// specialization of etl::logical_or when T is not specified, which leaves the
/// parameter types and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/logical_or_void
template <>
struct logical_or<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) || etl::forward<U>(rhs))
  {
    return lhs || rhs;
  }
};

/// \brief Function object for performing logical NOT (logical negation).
/// Effectively calls operator! for type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/logical_not
template <typename T = void>
struct logical_not
{
  [[nodiscard]] constexpr auto operator()(T const& arg) const -> bool
  {
    return !arg;
  }
};

/// \brief Function object for performing logical NOT (logical negation).
/// Effectively calls operator! for type T. The standard library provides a
/// specialization of etl::logical_not when T is not specified, which leaves the
/// parameter types and return type to be deduced.
///
/// \details
/// https://en.cppreference.com/w/cpp/utility/functional/logical_not_void
template <>
struct logical_not<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T>
  [[nodiscard]] constexpr auto operator()(T&& arg) const
    -> decltype(!etl::forward<T>(arg))
  {
    return !arg;
  }
};

/// \brief Function object for performing bitwise AND. Effectively
/// calls operator& on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_and
template <typename T = void>
struct bit_and
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs & rhs;
  }
};

/// \brief Function object for performing bitwise AND. Effectively
/// calls operator& on type T. The standard library provides a specialization of
/// etl::bit_and when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_and_void
template <>
struct bit_and<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) & etl::forward<U>(rhs))
  {
    return lhs & rhs;
  }
};

/// \brief Function object for performing bitwise OR. Effectively calls
/// operator| on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_or
template <typename T = void>
struct bit_or
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs | rhs;
  }
};

/// \brief Function object for performing bitwise OR. Effectively calls
/// operator| on type T. The standard library provides a specialization of
/// etl::bit_or when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_or_void
template <>
struct bit_or<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) | etl::forward<U>(rhs))
  {
    return lhs | rhs;
  }
};

/// \brief Function object for performing bitwise XOR. Effectively calls
/// operator^ on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_xor
template <typename T = void>
struct bit_xor
{
  [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T
  {
    return lhs ^ rhs;
  }
};

/// \brief Function object for performing bitwise XOR. Effectively calls
/// operator^ on type T. The standard library provides a specialization of
/// etl::bit_xor when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_xor_void
template <>
struct bit_xor<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T, typename U>
  [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
    -> decltype(etl::forward<T>(lhs) ^ etl::forward<U>(rhs))
  {
    return lhs ^ rhs;
  }
};

/// \brief Function object for performing bitwise NOT.
/// Effectively calls operator~ on type T.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_not
template <typename T = void>
struct bit_not
{
  [[nodiscard]] constexpr auto operator()(T const& arg) const -> T
  {
    return ~arg;
  }
};

/// \brief Function object for performing bitwise NOT. Effectively calls
/// operator~ on type T. The standard library provides a specialization of
/// etl::bit_not when T is not specified, which leaves the parameter types and
/// return type to be deduced.
///
/// \details https://en.cppreference.com/w/cpp/utility/functional/bit_not_void
template <>
struct bit_not<void>
{
  /// \brief The member type is_transparent indicates to the caller that this
  /// function object is a transparent function object: it accepts arguments of
  /// arbitrary types and uses perfect forwarding, which avoids unnecessary
  /// copying and conversion when the function object is used in heterogeneous
  /// context, or with rvalue arguments.
  using is_transparent = void;

  template <typename T>
  [[nodiscard]] constexpr auto operator()(T&& arg) const
    -> decltype(~etl::forward<T>(arg))
  {
    return ~arg;
  }
};

namespace detail
{
template <class T>
constexpr auto FUN(T& t) noexcept -> T&
{
  return t;
}

template <class T>
void FUN(T&&) = delete;

}  // namespace detail

/// \brief reference_wrapper is a class template that wraps a reference in a
/// copyable, assignable object. It is frequently used as a mechanism to store
/// references inside standard containers (like etl::static_vector) which cannot
/// normally hold references. Specifically, reference_wrapper is a
/// CopyConstructible and CopyAssignable wrapper around a reference to object or
/// reference to function of type T. Instances of reference_wrapper are objects
/// (they can be copied or stored in containers) but they are implicitly
/// convertible to T&, so that they can be used as arguments with the functions
/// that take the underlying type by reference. If the stored reference is
/// Callable, reference_wrapper is callable with the same arguments.
template <typename T>
struct reference_wrapper
{
  using type = T;

  /// \brief Constructs a new reference wrapper. Converts x to T& as if by T& t
  /// = forward<U>(x);, then stores a reference to t. This overload only
  /// participates in overload resolution if decay_t<U> is not the same type as
  /// reference_wrapper and the expression FUN(declval<U>()) is well-formed,
  /// where FUN names the set of imaginary functions:
  ///
  ///  void FUN(T&) noexcept;
  ///  void FUN(T&&) = delete;
  ///
  /// https://en.cppreference.com/w/cpp/utility/functional/reference_wrapper/reference_wrapper
  template <
    typename U,
    typename
    = decltype(detail::FUN<T>(declval<U>()),
               enable_if_t<!is_same_v<reference_wrapper, remove_cvref_t<U>>>())>
  constexpr reference_wrapper(U&& u) noexcept(
    noexcept(detail::FUN<T>(forward<U>(u))))
      : ptr_(addressof(detail::FUN<T>(forward<U>(u))))
  {
  }

  /// \brief Constructs a new reference wrapper. Copy constructor. Stores a
  /// reference to other.get().
  constexpr reference_wrapper(reference_wrapper const& x) noexcept = default;

  /// \brief Copy assignment operator. Drops the current reference and stores a
  /// reference to other.get().
  constexpr auto operator =(reference_wrapper const& x) noexcept
    -> reference_wrapper& = default;

  /// \brief Returns the stored reference.
  [[nodiscard]] constexpr operator type&() const noexcept { return *ptr_; }

  /// \brief Returns the stored reference.
  [[nodiscard]] constexpr auto get() const noexcept -> type& { return *ptr_; }

  /// \brief Calls the Callable object, reference to which is stored. This
  /// function is available only if the stored reference points to a Callable
  /// object. T must be a complete type.
  ///
  /// \returns The return value of the called function.
  template <typename... Args>
  constexpr auto operator()(Args&&... args) const
    noexcept(noexcept(invoke(get(), forward<Args>(args)...)))
      -> invoke_result_t<T&, Args...>
  {
    return invoke(get(), forward<Args>(args)...);
  }

  private:
  type* ptr_;
};

/// \brief One deduction guide is provided for std::reference_wrapper to support
/// deduction of the sole class template parameter.
///
/// https://en.cppreference.com/w/cpp/utility/functional/reference_wrapper/deduction_guides
template <typename T>
reference_wrapper(T&) -> reference_wrapper<T>;

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
[[nodiscard]] constexpr auto ref(T& t) noexcept -> reference_wrapper<T>
{
  return reference_wrapper<T>(t);
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
[[nodiscard]] constexpr auto ref(reference_wrapper<T> t) noexcept
  -> reference_wrapper<T>
{
  return ref(t.get());
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
[[nodiscard]] constexpr auto cref(T const& t) noexcept
  -> reference_wrapper<T const>
{
  return reference_wrapper<T const>(t);
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
[[nodiscard]] constexpr auto cref(reference_wrapper<T> t) noexcept
  -> reference_wrapper<T const>
{
  return cref(t.get());
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
void cref(T const&&) = delete;

template <typename>
class function_view;

template <typename Result, typename... Arguments>
class function_view<Result(Arguments...)>
{
  public:
  using result_type = Result;

  function_view(function_view const& other)
  {
    if (&other == this) { return; }
    if (createPtr_ != nullptr) { destroyPtr_(storage_); }
    if (other.createPtr_ != nullptr)
    {
      invokePtr_  = other.invokePtr_;
      createPtr_  = other.createPtr_;
      destroyPtr_ = other.destroyPtr_;
      createPtr_(storage_, const_cast<etl::byte*>(other.storage_));
    }
  }

  auto operator=(function_view const& other) noexcept -> function_view&
  {
    if (&other == this) { return *this; }
    if (createPtr_ != nullptr) { destroyPtr_(storage_); }
    if (other.createPtr_ != nullptr)
    {
      invokePtr_  = other.invokePtr_;
      createPtr_  = other.createPtr_;
      destroyPtr_ = other.destroyPtr_;
      createPtr_(storage_, const_cast<etl::byte*>(other.storage_));
    }

    return *this;
  }

  ~function_view() noexcept { destroyPtr_(storage_); }

  [[nodiscard]] auto operator()(Arguments&&... args) const -> result_type
  {
    return invokePtr_(const_cast<etl::byte*>(storage_),
                      etl::forward<Arguments>(args)...);  // NOLINT
  }

  protected:
  template <typename Functor>
  function_view(Functor f, etl::byte* storage)
      : invokePtr_ {reinterpret_cast<invoke_pointer_t>(invoke<Functor>)}
      , createPtr_ {reinterpret_cast<create_pointer_t>(create<Functor>)}
      , destroyPtr_ {reinterpret_cast<destroy_pointer_t>(destroy<Functor>)}
      , storage_ {storage}
  {
    createPtr_(storage_, &f);
  }

  private:
  template <typename Functor>
  static auto invoke(Functor* f, Arguments&&... args) -> Result
  {
    return (*f)(etl::forward<Arguments>(args)...);
  }

  template <typename Functor>
  static auto create(Functor* destination, Functor* source) -> void
  {
    new (destination) Functor(*source);
  }

  template <typename Functor>
  static auto destroy(Functor* f) -> void
  {
    f->~Functor();
  }

  using invoke_pointer_t  = Result (*)(void*, Arguments&&...);
  using create_pointer_t  = void (*)(void*, void*);
  using destroy_pointer_t = void (*)(void*);

  invoke_pointer_t invokePtr_   = nullptr;
  create_pointer_t createPtr_   = nullptr;
  destroy_pointer_t destroyPtr_ = nullptr;

  etl::byte* storage_ = nullptr;
};

template <size_t, typename>
class function;

template <size_t Capacity, typename Result, typename... Arguments>
class function<Capacity, Result(Arguments...)>
    : public function_view<Result(Arguments...)>
{
  public:
  template <typename Functor>
  function(Functor f)
      : function_view<Result(Arguments...)> {
        etl::forward<Functor>(f),
        storage_,
      }
  {
    static_assert(sizeof(Functor) <= sizeof(storage_));
  }

  private:
  etl::byte storage_[Capacity] {};
};

/// \brief Default searcher. A class suitable for use with Searcher overload of
/// etl::search that delegates the search operation to the pre-C++17 standard
/// library's etl::search.
template <typename ForwardIter, typename Predicate = equal_to<>>
class default_searcher
{
  public:
  default_searcher(ForwardIter f, ForwardIter l, Predicate p = Predicate())
      : first_(f), last_(l), predicate_(p)
  {
  }

  template <typename ForwardIter2>
  auto operator()(ForwardIter2 f, ForwardIter2 l) const
    -> etl::pair<ForwardIter2, ForwardIter2>
  {
    if (auto i = ::etl::detail::search_impl(f, l, first_, last_, predicate_);
        i != l)
    {
      auto j = ::etl::next(i, etl::distance(first_, last_));
      return etl::pair<ForwardIter2, ForwardIter2> {i, j};
    }

    return etl::pair<ForwardIter2, ForwardIter2> {l, l};
  }

  private:
  ForwardIter first_;
  ForwardIter last_;
  Predicate predicate_;
};

template <typename T>
struct hash;

template <>
struct hash<bool>
{
  [[nodiscard]] constexpr auto operator()(bool val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<char>
{
  [[nodiscard]] constexpr auto operator()(char val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<signed char>
{
  [[nodiscard]] constexpr auto operator()(signed char val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<unsigned char>
{
  [[nodiscard]] constexpr auto operator()(unsigned char val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<char16_t>
{
  [[nodiscard]] constexpr auto operator()(char16_t val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<char32_t>
{
  [[nodiscard]] constexpr auto operator()(char32_t val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<wchar_t>
{
  [[nodiscard]] constexpr auto operator()(wchar_t val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<short>
{
  [[nodiscard]] constexpr auto operator()(short val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<unsigned short>
{
  [[nodiscard]] constexpr auto operator()(unsigned short val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<int>
{
  [[nodiscard]] constexpr auto operator()(int val) const noexcept -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<unsigned int>
{
  [[nodiscard]] constexpr auto operator()(unsigned int val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<long>
{
  [[nodiscard]] constexpr auto operator()(long val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<long long>
{
  [[nodiscard]] constexpr auto operator()(long long val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<unsigned long>
{
  [[nodiscard]] constexpr auto operator()(unsigned long val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<unsigned long long>
{
  [[nodiscard]] constexpr auto operator()(unsigned long long val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<float>
{
  [[nodiscard]] constexpr auto operator()(float val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<double>
{
  [[nodiscard]] constexpr auto operator()(double val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};
template <>
struct hash<long double>
{
  [[nodiscard]] constexpr auto operator()(long double val) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(val);
  }
};

template <>
struct hash<etl::nullptr_t>
{
  [[nodiscard]] auto operator()(nullptr_t /*unused*/) const noexcept
    -> etl::size_t
  {
    return static_cast<etl::size_t>(0);
  }
};

template <typename T>
struct hash<T*>
{
  [[nodiscard]] auto operator()(T* val) const noexcept -> etl::size_t
  {
    return reinterpret_cast<etl::size_t>(val);
  }
};

}  // namespace etl

#endif  // TAETL_FUNCTIONAL_HPP