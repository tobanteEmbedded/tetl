// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPETRAITS_DECL_HPP
#define TETL_TYPETRAITS_DECL_HPP

namespace etl {
// primary type categories:
template <typename T>
struct is_void;
template <typename T>
struct is_null_pointer;
template <typename T>
struct is_integral;
template <typename T>
struct is_floating_point;
template <typename T>
struct is_array;
template <typename T>
struct is_pointer;
template <typename T>
struct is_lvalue_reference;
template <typename T>
struct is_rvalue_reference;
template <typename T>
struct is_member_object_pointer;
template <typename T>
struct is_member_function_pointer;
template <typename T>
struct is_enum;
template <typename T>
struct is_union;
template <typename T>
struct is_typename;
template <typename T>
struct is_function;

// composite type categories:
template <typename T>
struct is_reference;
template <typename T>
struct is_arithmetic;
template <typename T>
struct is_fundamental;
template <typename T>
struct is_object;
template <typename T>
struct is_scalar;
template <typename T>
struct is_compound;
template <typename T>
struct is_member_pointer;

template <typename T>
constexpr auto swap(T& a, T& b) noexcept -> void;

} // namespace etl

#endif // TETL_TYPETRAITS_DECL_HPP
