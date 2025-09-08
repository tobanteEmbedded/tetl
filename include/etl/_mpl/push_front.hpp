// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MPL_PUSH_FRONT_HPP
#define TETL_MPL_PUSH_FRONT_HPP

#include <etl/_mpl/list.hpp>

namespace etl::mpl {

/// \ingroup mpl
/// @{

template <typename T, typename List>
struct push_front;

template <typename T, typename... Ts>
struct push_front<T, list<Ts...>> {
    using type = list<T, Ts...>;
};

template <typename T, typename List>
using push_front_t = typename push_front<T, List>::type;

/// @}

} // namespace etl::mpl

#endif // TETL_MPL_PUSH_FRONT_HPP
