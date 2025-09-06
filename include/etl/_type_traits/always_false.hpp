// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_ALWAYS_FALSE_HPP
#define TETL_TYPE_TRAITS_ALWAYS_FALSE_HPP

namespace etl {

template <typename... T>
constexpr bool always_false = false;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALWAYS_FALSE_HPP
