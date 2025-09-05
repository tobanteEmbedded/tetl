// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MPL_HEAD_HPP
#define TETL_MPL_HEAD_HPP

#include <etl/_mpl/list.hpp>

namespace etl::mpl {

template <typename... Ts>
struct head;

template <typename Head, typename... Tail>
struct head<list<Head, Tail...>> {
    using type = Head;
};

template <typename List>
using head_t = typename head<List>::type;

} // namespace etl::mpl

#endif // TETL_MPL_HEAD_HPP
