/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_ALGORITHM_REMOVE_LAST_HPP
#define ETL_EXPERIMENTAL_META_ALGORITHM_REMOVE_LAST_HPP

#include "etl/experimental/meta/algorithm/remove_last_n.hpp"

#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

template <typename... Ts>
constexpr auto remove_last(etl::tuple<Ts...> t)
{
    return remove_last_n(size_c<1>, t);
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_ALGORITHM_REMOVE_LAST_HPP
