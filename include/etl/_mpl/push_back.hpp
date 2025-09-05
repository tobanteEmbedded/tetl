// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MPL_PUSH_BACK_HPP
#define TETL_MPL_PUSH_BACK_HPP

#include <etl/_mpl/list.hpp>

namespace etl::mpl {

/// \ingroup mpl
template <typename T, typename List>
struct push_back;

/// \ingroup mpl
template <typename T, typename... Ts>
struct push_back<T, list<Ts...>> {
    using type = list<Ts..., T>;
};

/// \ingroup mpl
template <typename T, typename List>
using push_back_t = typename push_back<T, List>::type;

} // namespace etl::mpl

#endif // TETL_MPL_PUSH_BACK_HPP
