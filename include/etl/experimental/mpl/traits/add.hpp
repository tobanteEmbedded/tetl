/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_MPL_TRAITS_ADD_HPP
#define ETL_EXPERIMENTAL_MPL_TRAITS_ADD_HPP

#include "etl/experimental/mpl/types/type.hpp"

#include "etl/type_traits.hpp"

namespace etl::experimental::mpl::traits {

#define TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(name)                                                                      \
    template <typename T>                                                                                              \
    constexpr auto name(type<T> const& /*unused*/)->type<typename etl::name<T>::type>                                  \
    {                                                                                                                  \
        return {};                                                                                                     \
    }

TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(add_const)
TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(add_cv)
TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(add_lvalue_reference)
TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(add_pointer)
TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(add_rvalue_reference)
TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION(add_volatile)

#undef TETL_MPL_DEFINE_TRAITS_ADD_FUNCTION

} // namespace etl::experimental::mpl::traits

#endif // ETL_EXPERIMENTAL_MPL_TRAITS_ADD_HPP
