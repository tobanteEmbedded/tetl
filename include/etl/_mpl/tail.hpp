// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MPL_TAIL_HPP
#define TETL_MPL_TAIL_HPP

#include <etl/_mpl/list.hpp>

namespace etl::mpl {

template <typename... Ts>
struct tail;

template <typename Head, typename... Tail>
struct tail<list<Head, Tail...>> {
    using type = list<Tail...>;
};

template <typename List>
using tail_t = typename tail<List>::type;

} // namespace etl::mpl

#endif // TETL_MPL_TAIL_HPP
