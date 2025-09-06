// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_INDEX_CONSTANT_HPP
#define TETL_TYPE_TRAITS_INDEX_CONSTANT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/integral_constant.hpp>

namespace etl {

template <size_t I>
using index_constant = integral_constant<size_t, I>;

template <size_t I>
inline constexpr auto index_v = index_constant<I>{};

} // namespace etl

#endif // TETL_TYPE_TRAITS_INDEX_CONSTANT_HPP
