// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_ALGORITHM_REMOVE_LAST_HPP
#define ETL_EXPERIMENTAL_MPL_ALGORITHM_REMOVE_LAST_HPP

#include "etl/experimental/mpl/algorithm/remove_last_n.hpp"

#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

template <typename... Ts>
constexpr auto remove_last(etl::tuple<Ts...> t)
{
    return remove_last_n(size_c<1>, t);
}

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_ALGORITHM_REMOVE_LAST_HPP
