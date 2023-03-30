// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_ALGORITHM_TRANSFORM_HPP
#define ETL_EXPERIMENTAL_MPL_ALGORITHM_TRANSFORM_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

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

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_ALGORITHM_TRANSFORM_HPP
