/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_MPL_ALGORITHM_ALL_OF_HPP
#define ETL_EXPERIMENTAL_MPL_ALGORITHM_ALL_OF_HPP

#include "etl/experimental/mpl/types/bool_constant.hpp"
#include "etl/experimental/mpl/types/type.hpp"

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

namespace detail {

template <etl::size_t... Is, typename... Ts, typename F>
constexpr auto all_of_impl(etl::index_sequence<Is...> /*is*/, tuple<Ts...>& t, F f)
{
    constexpr auto trueT = type<true_type>();
    if constexpr (((type<decltype(f(get<Is>(t)))> {} == trueT) && ...)) {
        return true_c;
    } else {
        return false_c;
    }
}

} // namespace detail

template <typename... Ts, typename F>
constexpr auto all_of(tuple<Ts...>& t, F f)
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    return detail::all_of_impl(indices, t, f);
}

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_ALGORITHM_ALL_OF_HPP