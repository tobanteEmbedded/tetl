/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_TRAITS_IS_HPP
#define ETL_EXPERIMENTAL_META_TRAITS_IS_HPP

#include "etl/experimental/meta/types/bool_constant.hpp"
#include "etl/experimental/meta/types/type.hpp"

namespace etl::experimental::meta::traits {

#define TETL_META_DEFINE_TRAITS_IS_FUNCTION(func)                              \
    template <typename T>                                                      \
        constexpr auto func(type<T>&& /*t*/)                                   \
            ->meta::bool_constant<etl::TETL_PP_CONCAT(func, _v) < T> >         \
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
