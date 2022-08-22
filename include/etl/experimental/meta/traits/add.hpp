/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_TRAITS_ADD_HPP
#define ETL_EXPERIMENTAL_META_TRAITS_ADD_HPP

#include "etl/experimental/meta/types/type.hpp"

#include "etl/type_traits.hpp"

namespace etl::experimental::meta::traits {

#define TETL_META_DEFINE_TRAITS_ADD_FUNCTION(name)                                                                     \
    template <typename T>                                                                                              \
    constexpr auto name(type<T> const& /*unused*/)->type<typename etl::name<T>::type>                                  \
    {                                                                                                                  \
        return {};                                                                                                     \
    }

TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_const)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_cv)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_lvalue_reference)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_pointer)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_rvalue_reference)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_volatile)

#undef TETL_META_DEFINE_TRAITS_ADD_FUNCTION

} // namespace etl::experimental::meta::traits

#endif // ETL_EXPERIMENTAL_META_TRAITS_ADD_HPP
