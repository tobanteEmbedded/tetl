// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_ALGORITHM_COUNT_IF_HPP
#define ETL_EXPERIMENTAL_MPL_ALGORITHM_COUNT_IF_HPP

#include "etl/experimental/mpl/types/integral_constant.hpp"
#include "etl/experimental/mpl/types/type.hpp"

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

namespace detail {

template <etl::size_t... I, typename... Ts, typename F>
constexpr auto count_if_impl(index_sequence<I...> /*is*/, tuple<Ts...>& t, F f)
{
    constexpr int c = ((type<decltype(f(get<I>(t)))>() == type<true_type>() ? 1 : 0) + ...);
    return mpl::integral_constant<int, c> {};
}

} // namespace detail

template <typename... Ts, typename F>
constexpr auto count_if(tuple<Ts...>& t, F f)
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    return detail::count_if_impl(indices, t, f);
}

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_ALGORITHM_COUNT_IF_HPP
