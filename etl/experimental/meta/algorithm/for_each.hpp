/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_ALGORITHM_FOR_EACH_HPP
#define ETL_EXPERIMENTAL_META_ALGORITHM_FOR_EACH_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

namespace detail {

template <bool WithI, etl::size_t... Index, typename... Ts, typename Func>
auto for_each_impl(
    etl::index_sequence<Index...> /*is*/, etl::tuple<Ts...>& t, Func f)
{
    if constexpr (WithI) {
        (f(Index, etl::get<Index>(t)), ...);
    } else {
        (f(etl::get<Index>(t)), ...);
    }
}
} // namespace detail

template <typename... Ts, typename Func>
constexpr auto for_each(etl::tuple<Ts...>& t, Func f) -> void
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    detail::for_each_impl<false>(indices, t, f);
}

template <typename... Ts, typename Func>
constexpr auto for_each_indexed(etl::tuple<Ts...>& t, Func f) -> void
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    detail::for_each_impl<true>(indices, t, f);
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_ALGORITHM_FOR_EACH_HPP
