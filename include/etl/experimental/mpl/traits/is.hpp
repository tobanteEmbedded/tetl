/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_MPL_TRAITS_IS_HPP
#define ETL_EXPERIMENTAL_MPL_TRAITS_IS_HPP

#include "etl/experimental/mpl/types/bool_constant.hpp"
#include "etl/experimental/mpl/types/type.hpp"

namespace etl::experimental::mpl::traits {

#define TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(func)                                                                       \
    template <typename T>                                                                                              \
        constexpr auto func(type<T>&& /*t*/)->mpl::bool_constant<etl::TETL_PP_CONCAT(func, _v) < T> >                  \
    {                                                                                                                  \
        return {};                                                                                                     \
    }

TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_abstract)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_aggregate)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_arithmetic)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_array)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_bounded_array)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_class)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_compound)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_const)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_copy_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_copy_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_default_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_destructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_empty)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_enum)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_final)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_floating_point)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_function)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_fundamental)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_integral)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_lvalue_reference)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_member_function_pointer)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_member_object_pointer)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_member_pointer)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_move_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_move_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_copy_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_copy_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_default_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_destructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_move_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_move_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_swappable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_null_pointer)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_object)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_pointer)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_polymorphic)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_reference)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_rvalue_reference)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_scalar)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_scoped_enum)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_signed)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_standard_layout)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_swappable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivial)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_copy_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_copy_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_copyable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_default_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_destructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_move_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_move_constructible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_unbounded_array)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_union)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_unsigned)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_void)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_volatile)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_reference_wrapper)

#undef TETL_MPL_DEFINE_TRAITS_IS_FUNCTION

#define TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(func)                                                                       \
    template <typename T, typename U>                                                                                  \
    constexpr auto func(type<T> /*l*/, type<U> /*r*/)->etl::func<T, U>                                                 \
    {                                                                                                                  \
        return {};                                                                                                     \
    }

TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_base_of)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_convertible)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_assignable)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_nothrow_swappable_with)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_same)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_swappable_with)
TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_trivially_assignable)

// TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_invocable_r)
// TETL_MPL_DEFINE_TRAITS_IS_FUNCTION(is_invocable)

#undef TETL_MPL_DEFINE_TRAITS_IS_FUNCTION

} // namespace etl::experimental::mpl::traits

#endif // ETL_EXPERIMENTAL_MPL_TRAITS_IS_HPP
