// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_ALGORITHM_TRANSFORM_HPP
#define ETL_EXPERIMENTAL_MPL_ALGORITHM_TRANSFORM_HPP

#include <etl/cstddef.hpp>
#include <etl/tuple.hpp>
#include <etl/type_traits.hpp>

namespace etl::experimental::mpl {

namespace detail {

template <size_t... Is, typename... Ts, typename F>
constexpr auto transform_impl(index_sequence<Is...> /*is*/, tuple<Ts...>& t, F f)
{
    return tuple<decltype(f(get<Is>(t)))...> {};
}

} // namespace detail

template <typename... Ts, typename F>
constexpr auto transform(tuple<Ts...>& t, F f)
{
    constexpr auto indices = make_index_sequence<sizeof...(Ts)> {};
    return detail::transform_impl(indices, t, f);
}

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_ALGORITHM_TRANSFORM_HPP
