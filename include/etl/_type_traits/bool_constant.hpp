// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP
#define TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP

#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

template <bool B>
using bool_constant = integral_constant<bool, B>;

using true_type  = bool_constant<true>;
using false_type = bool_constant<false>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP
