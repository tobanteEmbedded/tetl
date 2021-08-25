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

#ifndef ETL_EXPERIMENTAL_META_TRAITS_IS_HPP
#define ETL_EXPERIMENTAL_META_TRAITS_IS_HPP

#include "etl/experimental/meta/types/bool_constant.hpp"
#include "etl/experimental/meta/types/type.hpp"

namespace etl::experimental::meta::traits {

#define TETL_META_DEFINE_TRAITS_IS_FUNCTION(func)                              \
    template <typename T>                                                      \
    constexpr auto func(type<T> /*t*/)->etl::func<T>                           \
    {                                                                          \
        return {};                                                             \
    }

TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_abstract)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_aggregate)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_arithmetic)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_array)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_bounded_array)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_class)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_compound)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_const)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_copy_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_copy_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_default_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_destructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_empty)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_enum)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_final)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_floating_point)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_function)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_fundamental)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_integral)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_lvalue_reference)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_member_function_pointer)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_member_object_pointer)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_member_pointer)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_move_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_move_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_copy_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_copy_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_default_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_destructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_move_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_move_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_swappable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_null_pointer)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_object)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_pointer)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_polymorphic)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_reference)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_rvalue_reference)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_scalar)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_scoped_enum)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_signed)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_standard_layout)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_swappable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivial)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_copy_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_copy_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_copyable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_default_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_destructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_move_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_move_constructible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_unbounded_array)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_union)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_unsigned)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_void)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_volatile)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_reference_wrapper)

#undef TETL_META_DEFINE_TRAITS_IS_FUNCTION

#define TETL_META_DEFINE_TRAITS_IS_FUNCTION(func)                              \
    template <typename T, typename U>                                          \
    constexpr auto func(type<T> /*l*/, type<U> /*r*/)->etl::func<T, U>         \
    {                                                                          \
        return {};                                                             \
    }

TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_base_of)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_convertible)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_assignable)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_swappable_with)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_same)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_swappable_with)
TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_trivially_assignable)

// TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_invocable_r)
// TETL_META_DEFINE_TRAITS_IS_FUNCTION(is_invocable)

#undef TETL_META_DEFINE_TRAITS_IS_FUNCTION

} // namespace etl::experimental::meta::traits

#endif // ETL_EXPERIMENTAL_META_TRAITS_IS_HPP
