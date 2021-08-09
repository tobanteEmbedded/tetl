// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_TYPETRAITS_HPP
#define TETL_TYPETRAITS_HPP

#include "etl/version.hpp"

#include "etl/detail/cstddef/max_align_t.hpp"
#include "etl/detail/cstddef/nullptr_t.hpp"
#include "etl/detail/cstddef/ptrdiff_t.hpp"
#include "etl/detail/cstddef/size_t.hpp"

#include "etl/detail/type_traits/add_const.hpp"
#include "etl/detail/type_traits/add_cv.hpp"
#include "etl/detail/type_traits/add_lvalue_reference.hpp"
#include "etl/detail/type_traits/add_pointer.hpp"
#include "etl/detail/type_traits/add_rvalue_reference.hpp"
#include "etl/detail/type_traits/add_volatile.hpp"
#include "etl/detail/type_traits/bool_constant.hpp"
#include "etl/detail/type_traits/conditional.hpp"
#include "etl/detail/type_traits/conjunction.hpp"
#include "etl/detail/type_traits/declval.hpp"
#include "etl/detail/type_traits/disjunction.hpp"
#include "etl/detail/type_traits/enable_if.hpp"
#include "etl/detail/type_traits/extent.hpp"
#include "etl/detail/type_traits/index_sequence.hpp"
#include "etl/detail/type_traits/integer_sequence.hpp"
#include "etl/detail/type_traits/is_abstract.hpp"
#include "etl/detail/type_traits/is_aggregate.hpp"
#include "etl/detail/type_traits/is_array.hpp"
#include "etl/detail/type_traits/is_class.hpp"
#include "etl/detail/type_traits/is_const.hpp"
#include "etl/detail/type_traits/is_empty.hpp"
#include "etl/detail/type_traits/is_enum.hpp"
#include "etl/detail/type_traits/is_final.hpp"
#include "etl/detail/type_traits/is_floating_point.hpp"
#include "etl/detail/type_traits/is_function.hpp"
#include "etl/detail/type_traits/is_integral.hpp"
#include "etl/detail/type_traits/is_lvalue_reference.hpp"
#include "etl/detail/type_traits/is_member_pointer.hpp"
#include "etl/detail/type_traits/is_null_pointer.hpp"
#include "etl/detail/type_traits/is_pointer.hpp"
#include "etl/detail/type_traits/is_polymorphic.hpp"
#include "etl/detail/type_traits/is_reference.hpp"
#include "etl/detail/type_traits/is_rvalue_reference.hpp"
#include "etl/detail/type_traits/is_same.hpp"
#include "etl/detail/type_traits/is_union.hpp"
#include "etl/detail/type_traits/is_void.hpp"
#include "etl/detail/type_traits/is_volatile.hpp"
#include "etl/detail/type_traits/make_signed.hpp"
#include "etl/detail/type_traits/make_unsigned.hpp"
#include "etl/detail/type_traits/meta.hpp"
#include "etl/detail/type_traits/negation.hpp"
#include "etl/detail/type_traits/remove_all_extents.hpp"
#include "etl/detail/type_traits/remove_const.hpp"
#include "etl/detail/type_traits/remove_cv.hpp"
#include "etl/detail/type_traits/remove_cvref.hpp"
#include "etl/detail/type_traits/remove_extent.hpp"
#include "etl/detail/type_traits/remove_pointer.hpp"
#include "etl/detail/type_traits/remove_reference.hpp"
#include "etl/detail/type_traits/remove_volatile.hpp"
#include "etl/detail/type_traits/type_identity.hpp"
#include "etl/detail/type_traits/void_t.hpp"

#include "etl/detail/type_traits/has_virtual_destructor.hpp"
#include "etl/detail/type_traits/is_arithmetic.hpp"
#include "etl/detail/type_traits/is_assignable.hpp"
#include "etl/detail/type_traits/is_bounded_array.hpp"
#include "etl/detail/type_traits/is_compound.hpp"
#include "etl/detail/type_traits/is_constructible.hpp"
#include "etl/detail/type_traits/is_copy_assignable.hpp"
#include "etl/detail/type_traits/is_copy_constructible.hpp"
#include "etl/detail/type_traits/is_default_constructible.hpp"
#include "etl/detail/type_traits/is_destructible.hpp"
#include "etl/detail/type_traits/is_fundamental.hpp"
#include "etl/detail/type_traits/is_member_function_pointer.hpp"
#include "etl/detail/type_traits/is_member_object_pointer.hpp"
#include "etl/detail/type_traits/is_move_assignable.hpp"
#include "etl/detail/type_traits/is_move_constructible.hpp"
#include "etl/detail/type_traits/is_nothrow_assignable.hpp"
#include "etl/detail/type_traits/is_nothrow_constructible.hpp"
#include "etl/detail/type_traits/is_nothrow_copy_assignable.hpp"
#include "etl/detail/type_traits/is_nothrow_copy_constructible.hpp"
#include "etl/detail/type_traits/is_nothrow_default_constructible.hpp"
#include "etl/detail/type_traits/is_nothrow_destructible.hpp"
#include "etl/detail/type_traits/is_nothrow_move_assignable.hpp"
#include "etl/detail/type_traits/is_nothrow_move_constructible.hpp"
#include "etl/detail/type_traits/is_object.hpp"
#include "etl/detail/type_traits/is_scalar.hpp"
#include "etl/detail/type_traits/is_trivially_assignable.hpp"
#include "etl/detail/type_traits/is_trivially_constructible.hpp"
#include "etl/detail/type_traits/is_trivially_copy_assignable.hpp"
#include "etl/detail/type_traits/is_trivially_copy_constructible.hpp"
#include "etl/detail/type_traits/is_trivially_default_constructible.hpp"
#include "etl/detail/type_traits/is_trivially_destructible.hpp"
#include "etl/detail/type_traits/is_trivially_move_assignable.hpp"
#include "etl/detail/type_traits/is_trivially_move_constructible.hpp"
#include "etl/detail/type_traits/is_unbounded_array.hpp"

#include "etl/detail/type_traits/decl.hpp"

/// \file This header is part of the type support library.
namespace etl {

namespace detail {
template <bool, typename Type>
struct is_nothrow_destructible_helper;

template <typename Type>
struct is_nothrow_destructible_helper<false, Type> : ::etl::false_type {
};

template <typename Type>
struct is_nothrow_destructible_helper<true, Type>
    : ::etl::bool_constant<noexcept(::etl::declval<Type>().~Type())> {
};
} // namespace detail

/// \notes
/// [https://en.cppreference.com/w/cpp/types/is_destructible](https://en.cppreference.com/w/cpp/types/is_destructible)
/// \group is_nothrow_destructible
template <typename Type>
struct is_nothrow_destructible
    : detail::is_nothrow_destructible_helper<is_destructible_v<Type>, Type> {
};

/// \exclude
template <typename Type, size_t N>
struct is_nothrow_destructible<Type[N]> : is_nothrow_destructible<Type> {
};

/// \exclude
template <typename Type>
struct is_nothrow_destructible<Type&> : true_type {
};

/// \exclude
template <typename Type>
struct is_nothrow_destructible<Type&&> : true_type {
};

/// \group is_nothrow_destructible
template <typename T>
inline constexpr bool is_nothrow_destructible_v
    = is_nothrow_destructible<T>::value;

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_assignable : bool_constant<TETL_IS_ASSIGNABLE(T, U)> {
};

template <typename T, typename U>
inline constexpr bool is_assignable_v = is_assignable<T, U>::value;

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_trivially_assignable
    : bool_constant<TETL_IS_TRIVIALLY_ASSIGNABLE(T, U)> {
};

template <typename T, typename U>
inline constexpr bool is_trivially_assignable_v
    = is_trivially_assignable<T, U>::value;

namespace detail {
template <typename T, typename U>
struct is_nothrow_assignable_helper
    : ::etl::bool_constant<noexcept(
          ::etl::declval<T>() = ::etl::declval<U>())> {
};
} // namespace detail

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_nothrow_assignable
    : bool_constant<
          is_assignable_v<T,
              U> && detail::is_nothrow_assignable_helper<T, U>::value> {
};

template <typename T, typename U>
inline constexpr bool is_nothrow_assignable_v
    = is_nothrow_assignable<T, U>::value;

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_assignable<T&, T const&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_copy_assignable : is_assignable<add_lvalue_reference_t<T>,
                                add_lvalue_reference_t<const T>> {
};

template <typename T>
inline constexpr bool is_copy_assignable_v = is_copy_assignable<T>::value;

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_trivially_assignable<T&, T const&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_trivially_copy_assignable
    : is_trivially_assignable<add_lvalue_reference_t<T>,
          add_lvalue_reference_t<const T>> {
};

template <typename T>
inline constexpr bool is_trivially_copy_assignable_v
    = is_trivially_copy_assignable<T>::value;

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_nothrow_assignable<T&, T const&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_nothrow_copy_assignable
    : is_nothrow_assignable<add_lvalue_reference_t<T>,
          add_lvalue_reference_t<const T>> {
};

template <typename T>
inline constexpr bool is_nothrow_copy_assignable_v
    = is_nothrow_copy_assignable<T>::value;

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_assignable<T&, T&&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_move_assignable
    : is_assignable<add_lvalue_reference_t<T>, add_rvalue_reference_t<T>> {
};

template <typename T>
inline constexpr bool is_move_assignable_v = is_move_assignable<T>::value;

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_assignable<T&, T&&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_trivially_move_assignable
    : is_trivially_assignable<add_lvalue_reference_t<T>,
          add_rvalue_reference_t<T>> {
};

template <typename T>
inline constexpr bool is_trivially_move_assignable_v
    = is_trivially_move_assignable<T>::value;

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_assignable<T&, T&&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_nothrow_move_assignable
    : is_nothrow_assignable<add_lvalue_reference_t<T>,
          add_rvalue_reference_t<T>> {
};

template <typename T>
inline constexpr bool is_nothrow_move_assignable_v
    = is_nothrow_move_assignable<T>::value;

namespace detail {
struct nat {
    nat()           = delete;
    nat(nat const&) = delete;
    auto operator=(nat const&) -> nat& = delete;
    ~nat()                             = delete;
};

using ::etl::swap;
template <typename T>
void swap(nat a, nat b) noexcept;

template <typename T>
struct is_swappable_helper {
    using type = decltype(swap(::etl::declval<T&>(), ::etl::declval<T&>()));
    static const bool value = !::etl::is_same_v<type, nat>;
};

} // namespace detail

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_swappable_with<T&, T&>::value
template <typename T>
struct is_swappable : bool_constant<detail::is_swappable_helper<T>::value> {
};

template <typename T>
inline constexpr bool is_swappable_v = is_swappable<T>::value;

namespace detail {
template <bool, typename T>
struct is_nothrow_swappable_helper
    : ::etl::bool_constant<noexcept(
          swap(::etl::declval<T&>(), ::etl::declval<T&>()))> {
};
template <typename T>
struct is_nothrow_swappable_helper<false, T> : ::etl::false_type {
};
} // namespace detail

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_nothrow_swappable_with<T&, T&>::value
template <typename T>
struct is_nothrow_swappable
    : detail::is_nothrow_swappable_helper<is_swappable<T>::value, T> {
};

template <typename T>
inline constexpr bool is_nothrow_swappable_v = is_nothrow_swappable<T>::value;

namespace detail {
template <typename T, typename U, typename = void>
struct is_swappable_with_impl : false_type {
};

template <typename T, typename U>
struct is_swappable_with_impl<T, U,
    void_t<decltype(swap(declval<T>(), declval<U>()))>> : true_type {
};

} // namespace detail

/// \brief If the expressions swap(etl::declval<T>(), etl::declval<U>()) and
/// swap(etl::declval<U>(), etl::declval<T>()) are both well-formed in
/// unevaluated context after using etl::swap; provides the member constant
/// value equal true. Otherwise, value is false. Access checks are performed as
/// if from a context unrelated to either type.
template <typename T, typename U>
struct is_swappable_with
    : bool_constant<conjunction_v<detail::is_swappable_with_impl<T, U>,
          detail::is_swappable_with_impl<U, T>>> {
};

template <typename T, typename U>
inline constexpr bool is_swappable_with_v = is_swappable_with<T, U>::value;

/// \brief alignment_of
/// \group alignment_of
template <typename T>
struct alignment_of : integral_constant<size_t, alignof(T)> {
};

/// \group alignment_of
template <typename T>
inline constexpr size_t alignment_of_v = alignment_of<T>::value;

/// \brief If T is a TriviallyCopyable type, provides the member constant value
/// equal to true. For any other type, value is false. The only trivially
/// copyable types are scalar types, trivially copyable classes, and arrays of
/// such types/classes (possibly cv-qualified).
/// group is_trivial_copyable
template <typename T>
struct is_trivially_copyable {
private:
    // copy constructors
    static constexpr bool has_trivial_copy_ctor = is_copy_constructible_v<T>;
    static constexpr bool has_deleted_copy_ctor = !is_copy_constructible_v<T>;

    // move constructors
    static constexpr bool has_trivial_move_ctor = is_move_constructible_v<T>;
    static constexpr bool has_deleted_move_ctor = !is_move_constructible_v<T>;

    // copy assign
    static constexpr bool has_trivial_copy_assign = is_copy_assignable_v<T>;
    static constexpr bool has_deleted_copy_assign = !is_copy_assignable_v<T>;

    // move assign
    static constexpr bool has_trivial_move_assign = is_move_assignable_v<T>;
    static constexpr bool has_deleted_move_assign = !is_move_assignable_v<T>;

    // destructor
    static constexpr bool has_trivial_dtor = is_destructible_v<T>;

public:
    static constexpr bool value
        = has_trivial_dtor
          && (has_deleted_move_assign || has_trivial_move_assign)
          && (has_deleted_move_ctor || has_trivial_move_ctor)
          && (has_deleted_copy_assign || has_trivial_copy_assign)
          && (has_deleted_copy_ctor || has_trivial_copy_ctor);
};

/// group is_trivial_copyable
template <typename T>
struct is_trivially_copyable<T*> : true_type {
};

template <typename T>
inline constexpr bool is_trivially_copyable_v = is_trivially_copyable<T>::value;

/// \brief If T is TrivialType (that is, a scalar type, a trivially copyable
/// class with a trivial default constructor, or array of such type/class,
/// possibly cv-qualified), provides the member constant value equal to true.
/// For any other type, value is false.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_trivial](https://en.cppreference.com/w/cpp/types/is_trivial)
/// \group is_trivial
template <typename T>
struct is_trivial
    : bool_constant<is_trivially_copyable_v<
                        T> and is_trivially_default_constructible_v<T>> {
};

/// \group is_trivial
template <typename T>
inline constexpr bool is_trivial_v = is_trivial<T>::value;

/// \brief If T is a standard layout type (that is, a scalar type, a
/// standard-layout class, or an array of such type/class, possibly
/// cv-qualified), provides the member constant value equal to true. For any
/// other type, value is false.
template <typename T>
struct is_standard_layout : bool_constant<TETL_IS_STANDARD_LAYOUT(T)> {
};

template <typename T>
inline constexpr bool is_standard_layout_v = is_standard_layout<T>::value;

/// \brief If T is TriviallyCopyable and if any two objects of type T with the
/// same value have the same object representation, provides the member constant
/// value equal true. For any other type, value is false.
///
/// \details For the purpose of this trait, two arrays have the same value if
/// their elements have the same values, two non-union classes have the same
/// value if their direct subobjects have the same value, and two unions have
/// the same value if they have the same active member and the value of that
/// member is the same. It is implementation-defined which scalar types satisfy
/// this trait, but unsigned (until C++20) integer types that do not use padding
/// bits are guaranteed to have unique object representations. The behavior is
/// undefined if T is an incomplete type other than (possibly cv-qualified) void
/// or array of unknown bound. The behavior of a program that adds
/// specializations for has_unique_object_representations or
/// has_unique_object_representations_v is undefined.
template <typename T>
struct has_unique_object_representations
    : bool_constant<TETL_HAS_UNIQUE_OBJECT_REPRESENTATION(
          remove_cv_t<remove_all_extents_t<T>>)> {
};

template <typename T>
inline constexpr bool has_unique_object_representations_v
    = has_unique_object_representations<T>::value;

namespace detail {
template <typename T, bool = ::etl::is_arithmetic_v<T>>
struct is_unsigned : ::etl::bool_constant<T(0) < T(-1)> {
};

template <typename T>
struct is_unsigned<T, false> : ::etl::false_type {
};
} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(0) < T(-1): this results in true for the unsigned integer types
/// and the type bool and in false for the signed integer types and the
/// floating-point types. For any other type, value is false. The behavior of a
/// program that adds specializations for is_unsigned or is_unsigned_v (since
/// C++17) is undefined.
template <typename T>
struct is_unsigned : detail::is_unsigned<T>::type {
};

template <typename T>
inline constexpr bool is_unsigned_v = is_unsigned<T>::value;

namespace detail {
template <typename T, bool = ::etl::is_arithmetic_v<T>>
struct is_signed : ::etl::bool_constant<T(-1) < T(0)> {
};

template <typename T>
struct is_signed<T, false> : ::etl::false_type {
};
} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(-1) < T(0): this results in true for the floating-point types
/// and the signed integer types, and in false for the unsigned integer types
/// and the type bool. For any other type, value is false.
template <typename T>
struct is_signed : detail::is_signed<T>::type {
};

template <typename T>
inline constexpr bool is_signed_v = is_signed<T>::value;

namespace detail {
template <typename B>
auto test_pre_ptr_convertible(B const volatile*) -> ::etl::true_type;
template <typename>
auto test_pre_ptr_convertible(void const volatile*) -> ::etl::false_type;

template <typename, typename>
auto test_pre_is_base_of(...) -> ::etl::true_type;
template <typename B, typename D>
auto test_pre_is_base_of(int)
    -> decltype(test_pre_ptr_convertible<B>(static_cast<D*>(nullptr)));
} // namespace detail

/// \brief If Derived is derived from Base or if both are the same non-union
/// class (in both cases ignoring cv-qualification), provides the member
/// constant value equal to true. Otherwise value is false.
///
/// \details If both Base and Derived are non-union class types, and they are
/// not the same type (ignoring cv-qualification), Derived shall be a complete
/// type; otherwise the behavior is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_base_of](https://en.cppreference.com/w/cpp/types/is_base_of)
template <typename Base, typename Derived>
struct is_base_of
    : bool_constant<
          is_class_v<
              Base> and is_class_v<Derived>and decltype(detail::test_pre_is_base_of<Base, Derived>(0))::value> {
};

template <typename Base, typename Derived>
inline constexpr bool is_base_of_v = is_base_of<Base, Derived>::value;

/// \brief If Type is an array type, provides the member constant value equal to
/// the number of dimensions of the array. For any other type, value is 0. The
/// behavior of a program that adds specializations for rank or rank_v is
/// undefined.
template <typename T>
struct rank : integral_constant<size_t, 0> {
};

template <typename T>
struct rank<T[]> : integral_constant<size_t, rank<T>::value + 1> {
};

template <typename T, size_t N>
struct rank<T[N]> : integral_constant<size_t, rank<T>::value + 1> {
};

template <typename Type>
inline constexpr size_t rank_v = rank<Type>::value;

/// Applies lvalue-to-rvalue, array-to-pointer, and function-to-pointer implicit
/// conversions to the type T, removes cv-qualifiers, and defines the resulting
/// type as the member typedef type.
template <typename T>
struct decay {
private:
    using U = remove_reference_t<T>;

public:
    using type = conditional_t<is_array_v<U>, remove_extent_t<U>*,
        conditional_t<is_function_v<U>, add_pointer_t<U>, remove_cv_t<U>>>;
};

template <typename T>
using decay_t = typename decay<T>::type;

/// \brief Determines the common type among all types `T...`, that is the type
/// all `T...` can be implicitly converted to. If such a type exists, the member
/// type names that type. Otherwise, there is no member type. \notes
/// [cppreference.com/w/cpp/types/common_type](https://en.cppreference.com/w/cpp/types/common_type)
/// \group common_type
template <typename... T>
struct common_type;

/// \exclude
template <typename T>
struct common_type<T> : common_type<T, T> {
};

namespace detail {
template <typename T1, typename T2>
using cond_t = decltype(false ? ::etl::declval<T1>() : ::etl::declval<T2>());

template <typename T1, typename T2, typename = void>
struct common_type_2_impl {
};

template <typename T1, typename T2>
struct common_type_2_impl<T1, T2, void_t<cond_t<T1, T2>>> {
    using type = ::etl::decay_t<cond_t<T1, T2>>;
};

template <typename AlwaysVoid, typename T1, typename T2, typename... R>
struct common_type_multi_impl {
};

template <typename T1, typename T2, typename... R>
struct common_type_multi_impl<void_t<typename common_type<T1, T2>::type>, T1,
    T2, R...> : common_type<typename common_type<T1, T2>::type, R...> {
};
} // namespace detail

/// \exclude
template <typename T1, typename T2>
struct common_type<T1, T2>
    : detail::common_type_2_impl<decay_t<T1>, decay_t<T2>> {
};

/// \exclude
template <typename T1, typename T2, typename... R>
struct common_type<T1, T2, R...>
    : detail::common_type_multi_impl<void, T1, T2, R...> {
};

/// \group common_type
template <typename... T>
using common_type_t = typename common_type<T...>::type;

namespace detail {
template <typename>
using true_type_for = ::etl::true_type;

template <typename T>
auto test_returnable(int) -> true_type_for<T()>;
template <typename>
auto test_returnable(...) -> ::etl::false_type;

template <typename From, typename To>
auto test_nonvoid_convertible(int)
    -> true_type_for<decltype(::etl::declval<void (&)(To)>()(
        ::etl::declval<From>()))>;
template <typename, typename>
auto test_nonvoid_convertible(...) -> ::etl::false_type;

} // namespace detail

/// \brief If the imaginary function definition `To test() { return
/// etl::declval<From>(); }` is well-formed, (that is, either
/// `etl::declval<From>()` can be converted to To using implicit conversions, or
/// both From and To are possibly cv-qualified void), provides the member
/// constant value equal to true. Otherwise value is false. For the purposes of
/// this check, the use of `etl::declval` in the return statement is not
/// considered an odr-use. Access checks are performed as if from a context
/// unrelated to either type. Only the validity of the immediate context of the
/// expression in the return statement (including conversions to the return
/// type) is considered.
/// \group is_convertible
template <typename From, typename To>
struct is_convertible
    : bool_constant<(decltype(detail::test_returnable<To>(
                        0))::value&& decltype(detail::
                            test_nonvoid_convertible<From, To>(0))::value)
                    || (is_void_v<From> && is_void_v<To>)> {
};

/// \group is_convertible
template <typename From, typename To>
inline constexpr bool is_convertible_v = is_convertible<From, To>::value;

namespace detail {
template <typename T>
constexpr auto xforward(remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

template <typename T>
struct is_reference_wrapper : ::etl::false_type {
};

// TODO: Enable once reference_wrapper is implemented.
// template <typename U>
// struct is_reference_wrapper<::etl::reference_wrapper<U>> :
// ::etl::true_type
// {
// };

template <typename T>
struct invoke_impl {
    template <typename F, typename... Args>
    static auto call(F&& f, Args&&... args)
        -> decltype(xforward<F>(f)(xforward<Args>(args)...));
};

template <typename B, typename MT>
struct invoke_impl<MT B::*> {
    template <typename T, typename Td = ::etl::decay_t<T>,
        typename = ::etl::enable_if_t<::etl::is_base_of_v<B, Td>>>
    static auto get(T&& t) -> T&&;

    template <typename T, typename Td = ::etl::decay_t<T>,
        typename = ::etl::enable_if_t<is_reference_wrapper<Td>::value>>
    static auto get(T&& t) -> decltype(t.get());

    template <typename T, typename Td = ::etl::decay_t<T>,
        typename = ::etl::enable_if_t<!::etl::is_base_of_v<B, Td>>,
        typename = ::etl::enable_if_t<!is_reference_wrapper<Td>::value>>
    static auto get(T&& t) -> decltype(*xforward<T>(t));

    template <typename T, typename... Args, typename MT1,
        typename = ::etl::enable_if_t<::etl::is_function_v<MT1>>>
    static auto call(MT1 B::*pmf, T&& t, Args&&... args) -> decltype((
        invoke_impl::get(xforward<T>(t)).*pmf)(xforward<Args>(args)...));

    template <typename T>
    static auto call(MT B::*pmd, T&& t)
        -> decltype(invoke_impl::get(xforward<T>(t)).*pmd);
};

template <typename F, typename... Args, typename Fd = ::etl::decay_t<F>>
auto INVOKE(F&& f, Args&&... args)
    -> decltype(invoke_impl<Fd>::call(xforward<F>(f), xforward<Args>(args)...));

template <typename AlwaysVoid, typename, typename...>
struct invoke_result {
};
template <typename F, typename... Args>
struct invoke_result<decltype(void(detail::INVOKE(
                         ::etl::declval<F>(), ::etl::declval<Args>()...))),
    F, Args...> {
    using type = decltype(detail::INVOKE(
        ::etl::declval<F>(), ::etl::declval<Args>()...));
};
} // namespace detail

/// \brief Deduces the return type of an INVOKE expression at compile time.
/// F and all types in ArgTypes can be any complete type, array of unknown
/// bound, or (possibly cv-qualified) void. The behavior of a program that adds
/// specializations for any of the templates described on this page is
/// undefined. This implementation is copied from **cppreference.com**.
///
/// \notes
/// [cppreference.com/w/cpp/types/result_of](https://en.cppreference.com/w/cpp/types/result_of)
/// \group invoke_result
template <typename F, typename... ArgTypes>
struct invoke_result : detail::invoke_result<void, F, ArgTypes...> {
};

/// \group invoke_result
template <typename F, typename... ArgTypes>
using invoke_result_t = typename invoke_result<F, ArgTypes...>::type;

/// \brief Provides the nested type type, which is a trivial standard-layout
/// type suitable for use as uninitialized storage for any object whose size is
/// at most Len and whose alignment requirement is a divisor of Align.
/// The default value of Align is the most stringent (the largest)
/// alignment requirement for any object whose size is at most Len. If the
/// default value is not used, Align must be the value of alignof(T) for some
/// type T, or the behavior is undefined.
/// \group aligned_storage
template <size_t Len, size_t Align = alignof(max_align_t)>
struct aligned_storage {
    struct type {
        alignas(Align) unsigned char data[Len];
    };
};

/// \group aligned_storage
template <size_t Len, size_t Align = alignof(max_align_t)>
using aligned_storage_t = typename aligned_storage<Len, Align>::type;

namespace detail {
template <typename T>
[[nodiscard]] constexpr auto vmax(T val) -> T
{
    return val;
}

template <typename T0, typename T1, typename... Ts>
[[nodiscard]] constexpr auto vmax(T0 val1, T1 val2, Ts... vs) -> T0
{
    return (val1 > val2) ? vmax(val1, vs...) : vmax(val2, vs...);
}
} // namespace detail

/// \brief Provides the nested type type, which is a trivial standard-layout
/// type of a size and alignment suitable for use as uninitialized storage for
/// an object of any of the types listed in Types. The size of the storage is at
/// least Len. aligned_union also determines the strictest (largest) alignment
/// requirement among all Types and makes it available as the constant
/// alignment_value. If sizeof...(Types) == 0 or if any of the types in Types is
/// not a complete object type, the behavior is undefined. It is
/// implementation-defined whether any extended alignment is supported. The
/// behavior of a program that adds specializations for aligned_union is
/// undefined.
template <size_t Len, typename... Types>
struct aligned_union {
    static constexpr size_t alignment_value = detail::vmax(alignof(Types)...);

    struct type {
        alignas(
            alignment_value) char storage[detail::vmax(Len, sizeof(Types)...)];
    };
};

template <size_t Len, typename... Types>
using aligned_union_t = typename aligned_union<Len, Types...>::type;

namespace detail {
template <typename T, bool = is_enum_v<T>>
struct underlying_type_impl {
    using type = TETL_IS_UNDERLYING_TYPE(T);
};

template <typename T>
struct underlying_type_impl<T, false> {
};

} // namespace detail

/// \brief The underlying type of an enum.
template <typename T>
struct underlying_type : detail::underlying_type_impl<T> {
};

template <typename T>
using underlying_type_t = typename underlying_type<T>::type;

template <typename T, bool = is_enum_v<T>>
struct is_scoped_enum : false_type {
};

template <typename T>
struct is_scoped_enum<T, true>
    : bool_constant<!is_convertible_v<T, underlying_type_t<T>>> {
};

/// \brief Checks whether T is an scoped enumeration type. Provides the member
/// constant value which is equal to true, if T is an scoped enumeration type.
/// Otherwise, value is equal to false. The behavior of a program that adds
/// specializations for is_scoped_enum or is_scoped_enum_v is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_scoped_enum](https://en.cppreference.com/w/cpp/types/is_scoped_enum)
template <typename T>
inline constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;

/// \brief Detects whether the function call occurs within a constant-evaluated
/// context. Returns true if the evaluation of the call occurs within the
/// evaluation of an expression or conversion that is manifestly
/// constant-evaluated; otherwise returns false.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_constant_evaluated](https://en.cppreference.com/w/cpp/types/is_constant_evaluated)
[[nodiscard]] inline constexpr auto is_constant_evaluated() noexcept -> bool
{
    return TETL_IS_CONSTANT_EVALUATED();
}

} // namespace etl

#endif // TETL_TYPETRAITS_HPP