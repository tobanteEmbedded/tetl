// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_MPL_ALGORITHM_FOR_EACH_HPP
#define ETL_EXPERIMENTAL_MPL_ALGORITHM_FOR_EACH_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::mpl {

namespace detail {

template <bool WithI, etl::size_t... Index, typename... Ts, typename Func>
constexpr auto for_each_impl(etl::index_sequence<Index...> /*is*/, etl::tuple<Ts...>& t, Func f)
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

} // namespace etl::experimental::mpl

#endif // ETL_EXPERIMENTAL_MPL_ALGORITHM_FOR_EACH_HPP
