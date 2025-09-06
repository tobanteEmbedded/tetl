// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_ENABLE_IF_HPP
#define TETL_TYPE_TRAITS_ENABLE_IF_HPP

namespace etl {
/// Define a member typedef only if a boolean constant is true.
///
/// \include type_traits.cpp
template <bool, typename Type = void>
struct enable_if { };

template <typename Type>
struct enable_if<true, Type> {
    using type = Type;
};

template <bool B, typename T = void>
using enable_if_t = typename enable_if<B, T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ENABLE_IF_HPP
