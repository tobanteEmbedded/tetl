// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_APPLY_HPP
#define TETL_TUPLE_APPLY_HPP

#include <etl/_functional/invoke.hpp>
#include <etl/_tuple/tuple.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

namespace detail {
template <typename F, typename Tuple, etl::size_t... I>
constexpr auto apply_impl(F&& f, Tuple&& t, etl::index_sequence<I...> /*is*/) -> decltype(auto)
{
    return etl::invoke(TETL_FORWARD(f), etl::get<I>(TETL_FORWARD(t))...);
}
} // namespace detail

template <typename F, typename Tuple>
constexpr auto apply(F&& f, Tuple&& t) -> decltype(auto)
{
    return detail::apply_impl(
        TETL_FORWARD(f),
        TETL_FORWARD(t),
        etl::make_index_sequence<etl::tuple_size_v<etl::remove_reference_t<Tuple>>>{}
    );
}

} // namespace etl

#endif // TETL_TUPLE_APPLY_HPP
