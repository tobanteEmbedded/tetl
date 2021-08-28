/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP
#define TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP

#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

template <bool B>
using bool_constant = etl::integral_constant<bool, B>;

using true_type  = etl::bool_constant<true>;
using false_type = etl::bool_constant<false>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP
