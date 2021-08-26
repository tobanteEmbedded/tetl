/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_ALGORITHM_REVERSE_HPP
#define ETL_EXPERIMENTAL_META_ALGORITHM_REVERSE_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

namespace detail {
template <typename T, etl::size_t... I>
constexpr auto reverse_impl(T t, etl::index_sequence<I...> /*is*/)
{
    return etl::make_tuple(etl::get<sizeof...(I) - 1 - I>(t)...);
}
} // namespace detail

template <typename... Ts>
constexpr auto reverse(etl::tuple<Ts...> t)
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)>();
    return detail::reverse_impl(t, indices);
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_ALGORITHM_REVERSE_HPP
