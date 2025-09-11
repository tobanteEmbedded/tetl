// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP
#define TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP

#include <etl/_type_traits/integral_constant.hpp>

namespace etl {

/// \ingroup type_traits
template <bool B>
using bool_constant = integral_constant<bool, B>;

/// \ingroup type_traits
using true_type = bool_constant<true>;

/// \ingroup type_traits
using false_type = bool_constant<false>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_BOOL_CONSTANT_HPP
