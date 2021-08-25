/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_META_ALGORITHM_REMOVE_LAST_N_HPP
#define ETL_EXPERIMENTAL_META_ALGORITHM_REMOVE_LAST_N_HPP

#include "etl/experimental/meta/types/integral_constant.hpp"

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

namespace detail {
template <etl::size_t Count, typename Tuple>
struct remove_last_n_impl;

// template <>
// struct remove_last_n_impl<etl::tuple<>>; // Define as you wish or leave
// undefined

template <etl::size_t Count, typename... Args>
struct remove_last_n_impl<Count, etl::tuple<Args...>> {
private:
    using tuple_t = etl::tuple<Args...>;

    template <etl::size_t... N>
    static auto extract(etl::index_sequence<N...>)
        -> etl::tuple<etl::tuple_element_t<N, tuple_t>...>;

public:
    using type = decltype(extract(
        etl::make_index_sequence<sizeof...(Args) - Count>()));
};
template <etl::size_t Count, typename Tuple>
using remove_last_n_t = typename detail::remove_last_n_impl<Count, Tuple>::type;
} // namespace detail

template <etl::size_t Count, typename... Ts>
constexpr auto remove_last_n(
    etl::integral_constant<etl::size_t, Count> /*ic*/, etl::tuple<Ts...> /*t*/)
{
    return detail::remove_last_n_t<Count, etl::tuple<Ts...>>();
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_ALGORITHM_REMOVE_LAST_N_HPP
