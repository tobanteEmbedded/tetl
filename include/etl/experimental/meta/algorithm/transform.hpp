/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_ALGORITHM_TRANSFORM_HPP
#define ETL_EXPERIMENTAL_META_ALGORITHM_TRANSFORM_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

namespace detail {

template <etl::size_t... Is, typename... Ts, typename F>
constexpr auto transform_impl(etl::index_sequence<Is...> /*is*/, tuple<Ts...>& t, F f)
{
    return etl::tuple<decltype(f(get<Is>(t)))...> {};
}

} // namespace detail

template <typename... Ts, typename F>
constexpr auto transform(tuple<Ts...>& t, F f)
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    return detail::transform_impl(indices, t, f);
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_ALGORITHM_TRANSFORM_HPP
